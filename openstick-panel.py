#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
openstick-panel: panel web para el stick 4G OpenStick (UZ801) con puente Meshtastic.

Solo usa la biblioteca estándar de Python. Se ejecuta como root (necesita
nmcli, mmcli, systemctl y tailscale).

Uso:
  openstick-panel serve [--bind IP,IP] [--port N]
  openstick-panel set-password
  openstick-panel bridge-run        (lo lanza el servicio meshtastic-bridge)
"""
import getpass
import glob
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("OSP_CONFIG", "/etc/openstick-panel/config.json")
BRIDGE_UNIT = "meshtastic-bridge"
BAUDS = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
LOG_UNITS = {
    "panel": "openstick-panel",
    "bridge": BRIDGE_UNIT,
    "tailscale": "tailscaled",
    "red": "NetworkManager",
    "modem": "ModemManager",
}
SESSION_TTL = 8 * 3600

DEFAULT_CONFIG = {
    "username": "admin",
    "password": None,
    "default_creds": False,
    "bind": ["tailscale", "192.168.100.1", "192.168.101.1"],
    "port": 80,
    "wifi_iface": "wlan0",
    "hotspot_con": "hotspot",
    "lte_con": "lte",
    "bridge": {"device": "", "baud": 115200, "port": 4403, "bind": "tailscale"},
    "apn_auto": True,
    "apn_saved": {},
    "apn_custom": [],
    "pin_auto": True,
    "pin_saved": {"by_iccid": {}, "last": ""},
}

# --------------------------------------------------------------------------
# Configuración y contraseña
# --------------------------------------------------------------------------
CFG_LOCK = threading.Lock()


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        for k, v in data.items():
            if k == "bridge" and isinstance(v, dict):
                cfg["bridge"].update(v)
            else:
                cfg[k] = v
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001
        print("config ilegible:", e, file=sys.stderr)
    return cfg


def save_config(cfg):
    with CFG_LOCK:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_PATH)


def make_pw(pw):
    salt = secrets.token_bytes(16)
    it = 200000
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, it)
    return {"salt": salt.hex(), "iter": it, "hash": h.hex()}


def check_pw(pw, rec):
    if not rec:
        return False
    try:
        h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"),
                                bytes.fromhex(rec["salt"]), int(rec["iter"]))
        return hmac.compare_digest(h.hex(), rec["hash"])
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------
# Sesiones y límite de intentos
# --------------------------------------------------------------------------
SESSIONS = {}
SLOCK = threading.Lock()
FAILS = {}


def new_session():
    tok = secrets.token_urlsafe(32)
    with SLOCK:
        SESSIONS[tok] = time.time() + SESSION_TTL
    return tok


def valid_session(tok):
    if not tok:
        return False
    with SLOCK:
        exp = SESSIONS.get(tok)
        if exp and exp > time.time():
            return True
        SESSIONS.pop(tok, None)
    return False


def drop_session(tok):
    with SLOCK:
        SESSIONS.pop(tok, None)


def too_many_fails(ip):
    now = time.time()
    with SLOCK:
        lst = [t for t in FAILS.get(ip, []) if now - t < 300]
        FAILS[ip] = lst
        return len(lst) >= 5


def add_fail(ip):
    with SLOCK:
        FAILS.setdefault(ip, []).append(time.time())


# --------------------------------------------------------------------------
# Utilidades de sistema
# --------------------------------------------------------------------------
def run(cmd, timeout=15, inp=None):
    """Ejecuta sin shell. Devuelve (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=inp)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "comando no encontrado: " + cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "tiempo agotado"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def split_terse(line):
    """Divide una línea de `nmcli -t` respetando \\: escapados."""
    parts, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def kv_lines(text):
    d = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def g(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d


def tailscale_ip():
    rc, out, _ = run(["tailscale", "ip", "-4"], timeout=5)
    if rc == 0 and out.strip():
        ip = out.split()[0].strip()
        try:
            ipaddress.IPv4Address(ip)
            return ip
        except ValueError:
            return None
    return None


def sys_info():
    info = {"hostname": socket.gethostname(), "kernel": platform.release()}
    try:
        with open("/proc/uptime") as f:
            info["uptime_s"] = int(float(f.read().split()[0]))
    except Exception:  # noqa: BLE001
        pass
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0])
        info["mem_total_mb"] = mem.get("MemTotal", 0) // 1024
        info["mem_avail_mb"] = mem.get("MemAvailable", 0) // 1024
        info["swap_total_mb"] = mem.get("SwapTotal", 0) // 1024
        info["swap_free_mb"] = mem.get("SwapFree", 0) // 1024
    except Exception:  # noqa: BLE001
        pass
    try:
        du = shutil.disk_usage("/")
        info["disk_total_gb"] = round(du.total / 1e9, 1)
        info["disk_free_gb"] = round(du.free / 1e9, 1)
    except Exception:  # noqa: BLE001
        pass
    temps = []
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            with open(p) as f:
                temps.append(int(f.read().strip()) / 1000.0)
        except Exception:  # noqa: BLE001
            pass
    if temps:
        info["temp_c"] = round(max(temps), 1)
    try:
        info["load"] = [round(x, 2) for x in os.getloadavg()]
    except Exception:  # noqa: BLE001
        pass
    return info


def net_info():
    rc, out, _ = run(["ip", "-j", "-4", "addr", "show"], timeout=5)
    res = []
    if rc == 0:
        try:
            for it in json.loads(out):
                name = it.get("ifname")
                if name == "lo":
                    continue
                addrs = ["%s/%s" % (a.get("local"), a.get("prefixlen")) for a in it.get("addr_info", [])]
                res.append({"name": name, "state": it.get("operstate"), "addrs": addrs})
        except Exception:  # noqa: BLE001
            pass
    return res


def active_connections():
    """Lista de (nombre, tipo, dispositivo) activas."""
    rc, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "con", "show", "--active"], timeout=8)
    res = []
    if rc == 0:
        for line in out.splitlines():
            p = split_terse(line)
            if len(p) >= 3:
                res.append((p[0], p[1], p[2]))
    return res


def active_wifi_con(ifc):
    for name, typ, dev in active_connections():
        if dev == ifc and typ in ("802-11-wireless", "wifi"):
            return name
    return None


def wifi_ip(ifc):
    rc, out, _ = run(["nmcli", "-g", "IP4.ADDRESS", "dev", "show", ifc], timeout=8)
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line
    return None


def internet_ok():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=2.5).close()
        return True
    except OSError:
        return False


def wifi_status(cfg):
    ifc = cfg["wifi_iface"]
    st = {"iface": ifc, "connection": active_wifi_con(ifc), "ip": wifi_ip(ifc)}
    st["is_hotspot"] = st["connection"] == cfg["hotspot_con"]
    rc, out, _ = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,CHAN", "dev", "wifi", "list",
                      "--rescan", "no"], timeout=8)
    if rc == 0:
        for line in out.splitlines():
            p = split_terse(line)
            if len(p) >= 4 and p[0].strip() == "*":
                st["ssid"], st["signal"], st["chan"] = p[1], p[2], p[3]
                break
    return st


def tailscale_status():
    rc, out, err = run(["tailscale", "status", "--json"], timeout=8)
    if rc != 0:
        return {"installed": rc != 127, "error": (err or out).strip()[:200]}
    try:
        d = json.loads(out)
    except Exception:  # noqa: BLE001
        return {"installed": True, "error": "respuesta no válida"}
    peers = d.get("Peer") or {}
    st = {
        "installed": True,
        "state": d.get("BackendState"),
        "ips": g(d, "Self", "TailscaleIPs", default=[]),
        "name": g(d, "Self", "HostName"),
        "peers": len(peers),
        "peers_online": sum(1 for p in peers.values() if p.get("Online")),
    }
    rc2, out2, _ = run(["tailscale", "debug", "prefs"], timeout=8)
    if rc2 == 0:
        try:
            st["accept_routes"] = bool(json.loads(out2).get("RouteAll"))
        except Exception:  # noqa: BLE001
            pass
    return st


def modem_status(cfg):
    st = {"present": False}
    out_modem = "{}"
    rc, out, err = run(["mmcli", "-L", "-J"], timeout=8)
    if rc == 127:
        st["error"] = "ModemManager no instalado"
        return st
    try:
        lst = json.loads(out).get("modem-list", [])
    except Exception:  # noqa: BLE001
        lst = []
    if lst:
        m = re.search(r"(\d+)$", lst[0])
        idx = m.group(1) if m else "0"
        rc, out, err = run(["mmcli", "-m", idx, "-J"], timeout=10)
        out_modem = out
        try:
            d = json.loads(out)
            st["present"] = True
            st["index"] = idx
            st["state"] = g(d, "modem", "generic", "state")
            st["power"] = g(d, "modem", "generic", "power-state")
            st["signal"] = g(d, "modem", "generic", "signal-quality", "value")
            st["tech"] = g(d, "modem", "generic", "access-technologies", default=[])
            st["manufacturer"] = g(d, "modem", "generic", "manufacturer")
            st["model"] = g(d, "modem", "generic", "model")
            st["revision"] = g(d, "modem", "generic", "revision")
            st["unlock"] = g(d, "modem", "generic", "unlock-required")
            st["unlock_retries"] = g(d, "modem", "generic", "unlock-retries", default=[]) or []
            st["operator"] = g(d, "modem", "3gpp", "operator-name")
            st["registration"] = g(d, "modem", "3gpp", "registration-state")
            st["imei"] = g(d, "modem", "3gpp", "imei")
            st["sim"] = g(d, "modem", "generic", "sim")
        except Exception:  # noqa: BLE001
            st["error"] = (err or out).strip()[:200]
    st["operator_code"] = None
    st["sim_operator"] = st["sim_code"] = st["iccid"] = None
    if st.get("present"):
        try:
            st["operator_code"] = g(json.loads(out_modem), "modem", "3gpp", "operator-code")
        except Exception:  # noqa: BLE001
            pass
        sm = re.search(r"(\d+)$", st.get("sim") or "")
        if sm:
            rc3, out3, _ = run(["mmcli", "-i", sm.group(1), "-J"], timeout=8)
            try:
                pr = g(json.loads(out3), "sim", "properties", default={}) or {}
                st["sim_operator"] = pr.get("operator-name") or None
                st["sim_code"] = pr.get("operator-code") or None
                st["iccid"] = pr.get("iccid") or None
            except Exception:  # noqa: BLE001
                pass
    lte = cfg["lte_con"]
    rc, out, _ = run(["nmcli", "-t", "-f", "gsm.apn,gsm.username", "con", "show", "id", lte], timeout=8)
    if rc == 0:
        kv = kv_lines(out)
        st["apn"] = kv.get("gsm.apn", "")
        st["apn_user"] = kv.get("gsm.username", "")
    st["lte_active"] = any(n == lte for n, _, _ in active_connections())
    return st


def svc_state(unit):
    _, a, _ = run(["systemctl", "is-active", unit], timeout=5)
    _, e, _ = run(["systemctl", "is-enabled", unit], timeout=5)
    return {"active": a.strip() or "desconocido", "enabled": e.strip() or "desconocido"}


def serial_devices():
    pats = ["/dev/ttyMSM*", "/dev/ttyHS*", "/dev/ttyHSL*", "/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyAMA*"]
    devs = []
    for p in pats:
        devs += glob.glob(p)
    return sorted(set(devs))


def bridge_clients(port):
    rc, out, _ = run(["ss", "-Htn", "state", "established", "(", "sport", "=", ":%d" % port, ")"], timeout=5)
    return len([ln for ln in out.splitlines() if ln.strip()]) if rc == 0 else 0


def bridge_info():
    cfg = load_config()
    b = cfg["bridge"]
    return {
        "config": b,
        "devices": serial_devices(),
        "device_exists": bool(b["device"]) and os.path.exists(b["device"]),
        "service": svc_state(BRIDGE_UNIT),
        "clients": bridge_clients(int(b["port"])),
        "tailscale_ip": tailscale_ip(),
        "bauds": BAUDS,
    }


def internet_via_iface(dev):
    """¿Hay salida a internet forzando la salida por esa interfaz?"""
    try:
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.settimeout(2.5)
        so.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode() + b"\0")
        so.connect(("1.1.1.1", 443))
        so.close()
        return True
    except OSError:
        return False


def internet_info(cfg=None, net=None):
    """Salida a internet en general y por cada vía (WiFi y 4G) por separado."""
    cfg = cfg or load_config()
    net = net if net is not None else net_info()
    have = {n["name"]: n for n in net if n.get("addrs")}
    paths = {}
    cands = []
    ifc = cfg["wifi_iface"]
    if ifc in have and active_wifi_con(ifc) not in (None, cfg["hotspot_con"]):
        cands.append(("wifi", ifc))
    for n in sorted(have):
        if n.startswith("wwan"):
            cands.append(("4g", n))
            break
    results = {}

    def work(label, dev):
        results[label] = internet_via_iface(dev)

    ths = [threading.Thread(target=work, args=c, daemon=True) for c in cands]
    general = {}
    th_gen = threading.Thread(target=lambda: general.update(ok=internet_ok()), daemon=True)
    for t in ths + [th_gen]:
        t.start()
    for t in ths + [th_gen]:
        t.join(timeout=6)
    for label, dev in cands:
        paths[label] = {"iface": dev, "ok": bool(results.get(label))}
    via = None
    rc, out, _ = run(["ip", "-j", "route", "get", "1.1.1.1"], timeout=4)
    if rc == 0:
        try:
            via = json.loads(out)[0].get("dev")
        except Exception:  # noqa: BLE001
            via = None
    ok = bool(general.get("ok")) or any(p["ok"] for p in paths.values())
    return {"ok": ok, "via": via, "paths": paths}


def get_status():
    cfg = load_config()
    net = net_info()
    return {
        "internet": internet_info(cfg, net),
        "system": sys_info(),
        "net": net,
        "wifi": wifi_status(cfg),
        "tailscale": tailscale_status(),
        "modem": modem_status(cfg),
        "bridge": bridge_info(),
        "panel_port": cfg["port"],
        "auth": {"user": cfg.get("username") or "admin", "default_creds": bool(cfg.get("default_creds"))},
    }


# --------------------------------------------------------------------------
# Tareas en segundo plano (con rescate para el WiFi)
# --------------------------------------------------------------------------
JOB = {"name": None, "running": False, "ok": None, "log": [], "started": 0}
JOB_LOCK = threading.Lock()


def jlog(msg):
    JOB["log"].append(time.strftime("%H:%M:%S ") + msg)


def start_job(name, fn, *args):
    with JOB_LOCK:
        if JOB["running"]:
            return False
        JOB.update(name=name, running=True, ok=None, log=[], started=time.time())

    def runner():
        try:
            ok = fn(*args)
        except Exception as e:  # noqa: BLE001
            jlog("Error interno: %s" % e)
            ok = False
        with JOB_LOCK:
            JOB["running"] = False
            JOB["ok"] = bool(ok)

    threading.Thread(target=runner, daemon=True).start()
    return True


def saved_wifi_names():
    rc, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"], timeout=8)
    names = set()
    if rc == 0:
        for line in out.splitlines():
            p = split_terse(line)
            if len(p) >= 2 and p[1] in ("802-11-wireless", "wifi"):
                names.add(p[0])
    return names


def wifi_connect_job(ssid, pw):
    cfg = load_config()
    ifc, hot = cfg["wifi_iface"], cfg["hotspot_con"]
    before = saved_wifi_names()
    prev = active_wifi_con(ifc)
    jlog("Conexión WiFi actual: %s" % (prev or "ninguna"))
    if prev == hot:
        jlog("Apagando el punto de acceso para poder usar el WiFi como cliente…")
        run(["nmcli", "con", "down", "id", hot], timeout=20)
        time.sleep(3)
    jlog("Conectando a «%s»…" % ssid)
    cmd = ["nmcli", "-w", "40", "dev", "wifi", "connect", ssid]
    if pw:
        cmd += ["password", pw]
    cmd += ["ifname", ifc]
    rc, out, err = run(cmd, timeout=60)
    if rc == 0:
        jlog("Asociado. Esperando dirección IP…")
        ip = None
        for _ in range(20):
            ip = wifi_ip(ifc)
            if ip:
                break
            time.sleep(1)
        if ip:
            jlog("IP: %s" % ip)
            jlog("Internet: %s" % ("sí" if internet_ok() else "no responde (puede ser solo red local)"))
            return True
        jlog("No se recibió dirección IP. Se restablece la conexión anterior…")
    else:
        jlog("Fallo: " + (err or out).strip()[:300])
    if ssid not in before:
        run(["nmcli", "con", "delete", "id", ssid], timeout=10)
    target = prev if prev else hot
    jlog("Recuperación: se restablece la conexión «%s»…" % target)
    rc, out, err = run(["nmcli", "-w", "30", "con", "up", "id", target], timeout=45)
    if rc != 0 and target != hot:
        jlog("No ha sido posible; se activa el punto de acceso «%s»…" % hot)
        rc, out, err = run(["nmcli", "-w", "30", "con", "up", "id", hot], timeout=45)
    jlog("Recuperación " + ("correcta" if rc == 0 else "fallida: " + (err or out).strip()[:200]))
    return False


def hotspot_job(on):
    cfg = load_config()
    hot = cfg["hotspot_con"]
    if on:
        jlog("Activando punto de acceso «%s»…" % hot)
        rc, out, err = run(["nmcli", "-w", "30", "con", "up", "id", hot], timeout=45)
    else:
        jlog("Apagando punto de acceso y buscando una red WiFi guardada…")
        run(["nmcli", "con", "down", "id", hot], timeout=20)
        time.sleep(2)
        rc, out, err = run(["nmcli", "-w", "30", "dev", "connect", cfg["wifi_iface"]], timeout=45)
    jlog("Hecho." if rc == 0 else "Error: " + (err or out).strip()[:200])
    return rc == 0


def lte_job(on, restart=False):
    cfg = load_config()
    lte = cfg["lte_con"]
    if on and restart:
        jlog("Reiniciando la conexión de datos para aplicar el APN…")
        run(["nmcli", "con", "down", "id", lte], timeout=20)
        time.sleep(2)
    jlog(("Conectando «%s»…" if on else "Desconectando «%s»…") % lte)
    rc, out, err = run(["nmcli", "-w", "40", "con", "up" if on else "down", "id", lte], timeout=55)
    jlog("Hecho." if rc == 0 else "Error: " + (err or out).strip()[:300])
    return rc == 0



# --------------------------------------------------------------------------
# APN: típicos por operador, detección de la SIM y prueba automática
# --------------------------------------------------------------------------
# (grupo, etiqueta, apn, usuario, clave). Datos de blogs de terceros: por eso
# hay variantes y el panel puede probarlas una a una.
APN_PRESETS = [
    ("movistar", "Movistar", "movistar.es", "MOVISTAR", "MOVISTAR"),
    ("movistar", "Movistar / O2 (alternativo)", "telefonica.es", "telefonica", "telefonica"),
    ("orange", "Orange", "orangeworld", "orange", "orange"),
    ("orange", "Orange (sin usuario)", "orangeworld", "", ""),
    ("vodafone", "Vodafone", "airtelwap.es", "vodafone", "vodafone"),
    ("vodafone", "Vodafone (alternativo)", "airtelwap.es", "wap@wap", "wap125"),
    ("yoigo", "Yoigo", "internet", "", ""),
    ("masmovil", "MásMóvil", "internet", "", ""),
    ("masmovil", "MásMóvil (alternativo)", "internetmas", "", ""),
    ("digi", "Digi", "internet.digimobil.es", "", ""),
    ("digi", "Digi (con usuario)", "internet.digimobil.es", "digi", "digi"),
    ("pepephone", "Pepephone", "gprsmov.pepephone.com", "", ""),
    ("lowi", "Lowi", "lowi.private.omv.es", "", ""),
    ("lowi", "Lowi (alternativo)", "lowi.private", "", ""),
    ("simyo", "Simyo", "gprs-service.com", "", ""),
    ("jazztel", "Jazztel", "jazzinternet", "", ""),
    ("euskaltel", "Euskaltel", "internet.euskaltel.mobi", "CLIENTE", "EUSKALTEL"),
    ("lycamobile", "Lycamobile", "data.lycamobile.es", "lmes", "plus"),
    ("finetwork", "Finetwork", "fi.omv.es", "", ""),
    ("finetwork", "Finetwork (alternativo)", "fi.network", "", ""),
    ("lebara", "Lebara", "gprsmov.lebaramobile.es", "", ""),
    ("hits", "Hits Mobile", "tel.hitsmobile.es", "", ""),
    ("telecable", "Telecable", "internet.telecable.es", "", ""),
    ("generico", "Genérico: internet", "internet", "", ""),
    ("generico", "Genérico: inet.es", "inet.es", "", ""),
    ("generico", "Genérico: datos", "datos", "", ""),
    ("generico", "Genérico: euinternet", "euinternet", "", ""),
]
GROUP_NAMES = {
    "movistar": "Movistar / O2", "orange": "Orange", "vodafone": "Vodafone", "yoigo": "Yoigo",
    "masmovil": "MásMóvil", "digi": "Digi", "pepephone": "Pepephone", "lowi": "Lowi",
    "simyo": "Simyo", "jazztel": "Jazztel", "euskaltel": "Euskaltel", "lycamobile": "Lycamobile",
    "finetwork": "Finetwork", "lebara": "Lebara", "hits": "Hits Mobile", "telecable": "Telecable",
    "generico": "Genéricos (OMV pequeños)",
}
GROUP_RX = {
    "movistar": r"movistar|telef[oó]nica|\bo2\b", "orange": r"orange", "vodafone": r"vodafone",
    "yoigo": r"yoigo", "masmovil": r"m[aá]sm[oó]vil|masmovil", "digi": r"\bdigi", "pepephone": r"pepephone",
    "lowi": r"lowi", "simyo": r"simyo", "jazztel": r"jazztel", "euskaltel": r"euskaltel",
    "lycamobile": r"lyca", "finetwork": r"finetwork|fi network", "lebara": r"lebara",
    "hits": r"\bhits", "telecable": r"telecable",
}
CODE_GROUPS = {"21401": "vodafone", "21403": "orange", "21404": "yoigo", "21407": "movistar"}
APN_MAX_TRIES = 10
APN_TRIED = {}


def modem_locked(m):
    return m.get("state") == "locked" or bool(
        re.match(r"^(sim-pin|sim-puk|ph-[a-z-]+|network-[a-z-]+)$", m.get("unlock") or ""))


def detect_groups(m):
    res = []

    def add(gk):
        if gk and gk not in res:
            res.append(gk)

    for name, code in ((m.get("sim_operator"), m.get("sim_code")), (m.get("operator"), m.get("operator_code"))):
        t = (name or "").lower()
        for gk, rx in GROUP_RX.items():
            if re.search(rx, t):
                add(gk)
        add(CODE_GROUPS.get(str(code or "")))
    return res


def apn_candidates(cfg, m):
    out, seen = [], set()

    def add(label, apn, user, pw):
        k = (apn, user, pw)
        if k not in seen:
            seen.add(k)
            out.append({"label": label, "apn": apn, "user": user, "password": pw})

    saved = (cfg.get("apn_saved") or {}).get(m.get("iccid") or "")
    if saved:
        add("guardado para esta SIM", saved.get("apn", ""), saved.get("user", ""), saved.get("password", ""))
    for c in cfg.get("apn_custom") or []:
        add(c.get("label", "personalizado"), c.get("apn", ""), c.get("user", ""), c.get("password", ""))
    groups = detect_groups(m)
    for gk in groups:
        for gg, label, a, u, pw in APN_PRESETS:
            if gg == gk:
                add(label, a, u, pw)
    for gg, label, a, u, pw in APN_PRESETS:
        if gg not in groups and gg != "generico":
            add(label, a, u, pw)
    for gg, label, a, u, pw in APN_PRESETS:
        if gg == "generico":
            add(label, a, u, pw)
    return out


def current_apn(cfg):
    rc, out, _ = run(["nmcli", "-s", "-t", "-f", "gsm.apn,gsm.username,gsm.password", "con", "show", "id",
                      cfg["lte_con"]], timeout=8)
    kv = kv_lines(out) if rc == 0 else {}
    return {"apn": kv.get("gsm.apn", ""), "user": kv.get("gsm.username", ""), "password": kv.get("gsm.password", "")}


def set_apn(cfg, c):
    return run(["nmcli", "con", "modify", "id", cfg["lte_con"], "gsm.apn", c["apn"], "gsm.username", c["user"],
                "gsm.password", c["password"]], timeout=15)


def wwan_iface():
    for n in net_info():
        if n["name"].startswith("wwan") and n["addrs"]:
            return n["name"]
    return None


def apn_try(cfg, c):
    """Aplica el APN, reconecta y comprueba que hay internet por el 4G."""
    lte = cfg["lte_con"]
    rc, out, e = set_apn(cfg, c)
    if rc != 0:
        jlog("  no se pudo guardar: " + (e or out).strip()[:150])
        return False
    run(["nmcli", "con", "down", "id", lte], timeout=20)
    time.sleep(2)
    rc, out, e = run(["nmcli", "-w", "30", "con", "up", "id", lte], timeout=45)
    if rc != 0:
        jlog("  no conecta")
        return False
    dev = None
    for _ in range(8):
        dev = wwan_iface()
        if dev:
            break
        time.sleep(1)
    if not dev:
        jlog("  conecta pero no recibe IP")
        return False
    for _ in range(4):
        if internet_via_iface(dev):
            return True
        time.sleep(2)
    jlog("  conecta pero sin salida a internet")
    return False


def remember_apn(cfg, iccid, c, label=""):
    if not iccid:
        return
    cfg = load_config()
    cfg.setdefault("apn_saved", {})[iccid] = {"apn": c["apn"], "user": c["user"], "password": c["password"],
                                              "label": label or c.get("label", ""), "at": int(time.time())}
    save_config(cfg)


def apn_probe_job(auto=False):
    cfg = load_config()
    m = modem_status(cfg)
    if not m.get("present") or not m.get("sim") or m.get("sim") == "--":
        jlog("No hay SIM detectada.")
        return False
    if modem_locked(m):
        jlog("La SIM está bloqueada: introduzca primero el PIN.")
        return False
    iccid = m.get("iccid") or ""
    APN_TRIED[iccid] = APN_TRIED.get(iccid, 0) + 1
    jlog("SIM: %s · red: %s" % (m.get("sim_operator") or "desconocida", m.get("operator") or "sin registrar"))
    cands = apn_candidates(cfg, m)[:APN_MAX_TRIES]
    prev = current_apn(cfg)
    for i, c in enumerate(cands, 1):
        jlog("(%d/%d) Probando «%s» — %s…" % (i, len(cands), c["apn"], c["label"]))
        if apn_try(cfg, c):
            remember_apn(cfg, iccid, c)
            jlog("Conexión correcta. APN «%s» guardado para esta SIM." % c["apn"])
            return True
    jlog("Ningún APN ofreció acceso a internet. Se conserva el anterior («%s»)." % (prev.get("apn") or "vacío"))
    set_apn(cfg, prev)
    run(["nmcli", "-w", "30", "con", "up", "id", cfg["lte_con"]], timeout=45)
    return False


def apply_saved_job(saved):
    cfg = load_config()
    m = modem_status(cfg)
    jlog("SIM conocida: se aplica el APN guardado «%s»…" % saved.get("apn"))
    if apn_try(cfg, saved):
        jlog("Datos conectados.")
        return True
    jlog("El APN guardado ya no funciona. Se buscará otro…")
    c2 = load_config()
    c2.get("apn_saved", {}).pop(m.get("iccid") or "", None)
    save_config(c2)
    return apn_probe_job(True)


def apn_watch_once():
    cfg = load_config()
    if not cfg.get("apn_auto", True) or JOB["running"]:
        return
    m = modem_status(cfg)
    iccid = m.get("iccid")
    if (not m.get("present")) or (not m.get("sim")) or m.get("sim") == "--" or not iccid or modem_locked(m):
        return
    if m.get("registration") not in ("home", "roaming"):
        return
    saved = (cfg.get("apn_saved") or {}).get(iccid)
    if saved:
        if (m.get("apn") or "") != saved.get("apn", ""):
            APN_TRIED[iccid] = 1
            start_job("Aplicar APN recordado", apply_saved_job, saved)
        return
    if m.get("lte_active") and m.get("state") == "connected":
        dev = wwan_iface()
        if dev and internet_via_iface(dev):
            remember_apn(cfg, iccid, current_apn(cfg), "el que ya funcionaba")
        return
    if APN_TRIED.get(iccid, 0) >= 1:
        return
    APN_TRIED[iccid] = 1
    start_job("Buscar APN automáticamente", apn_probe_job, True)


def apn_watch():
    time.sleep(45)
    while True:
        try:
            if not pin_watch_once():
                apn_watch_once()
        except Exception as e:  # noqa: BLE001
            print("apn_watch:", e, file=sys.stderr, flush=True)
        time.sleep(20)



# --------------------------------------------------------------------------
# PIN: recordar el último y desbloquear la SIM al arrancar
# --------------------------------------------------------------------------
PIN_TRIED = {}


def pin_retries(m):
    """Intentos de PIN que quedan (None si el módem no lo dice)."""
    for x in m.get("unlock_retries") or []:
        mm = re.match(r"^sim-pin \((\d+)\)$", str(x))
        if mm:
            return int(mm.group(1))
    return None


def sim_index(m):
    mm = re.search(r"(\d+)$", m.get("sim") or "")
    return mm.group(1) if mm else None


def remember_pin(iccid, pin):
    cfg = load_config()
    ps = cfg.get("pin_saved") or {"by_iccid": {}, "last": ""}
    ps.setdefault("by_iccid", {})
    ps["last"] = pin
    if iccid:
        ps["by_iccid"][iccid] = pin
    cfg["pin_saved"] = ps
    save_config(cfg)


def forget_pin(iccid=None, everything=False):
    cfg = load_config()
    ps = cfg.get("pin_saved") or {"by_iccid": {}, "last": ""}
    if everything:
        ps = {"by_iccid": {}, "last": ""}
    else:
        if iccid:
            ps.get("by_iccid", {}).pop(iccid, None)
        ps["last"] = ""
    cfg["pin_saved"] = ps
    save_config(cfg)


def pin_unlock_job(pin, key):
    cfg = load_config()
    m = modem_status(cfg)
    idx = sim_index(m)
    if idx is None:
        jlog("No se detecta la SIM.")
        return False
    jlog("La SIM solicita PIN. Se aplica el PIN guardado…")
    rc, out, e = run(["mmcli", "-i", idx, "--pin=" + pin], timeout=25)
    if rc == 0:
        jlog("SIM desbloqueada.")
        return True
    jlog("El PIN guardado no ha sido aceptado: " + (e or out).strip()[:150])
    jlog("Se elimina el PIN guardado para no agotar los intentos. Introdúzcalo manualmente en la pestaña SIM.")
    forget_pin(key)
    return False


def pin_watch_once():
    cfg = load_config()
    if not cfg.get("pin_auto", True) or JOB["running"]:
        return False
    m = modem_status(cfg)
    if not m.get("present") or not m.get("sim") or m.get("sim") == "--":
        return False
    if m.get("unlock") != "sim-pin":
        return False
    ps = cfg.get("pin_saved") or {}
    key = m.get("iccid") or ""
    pin = (ps.get("by_iccid") or {}).get(key) if key else None
    if not pin:
        pin = ps.get("last") or ""
    if not pin:
        return False
    if PIN_TRIED.get(key or "?", 0) >= 1:
        return False
    left = pin_retries(m)
    # Máximo un intento automático por SIM y arranque, y solo con los 3 intentos completos
    if left is not None and left < 3:
        return False
    PIN_TRIED[key or "?"] = 1
    return start_job("Desbloquear la SIM", pin_unlock_job, pin, key)


# --------------------------------------------------------------------------
# Puente Meshtastic (socat serie <-> TCP)
# --------------------------------------------------------------------------
def probe_serial(dev, baud):
    """Despierta el nodo y pide la configuración; devuelve los bytes recibidos."""
    import termios
    fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        attrs = termios.tcgetattr(fd)
        speed = getattr(termios, "B%d" % baud)
        attrs[0] = 0
        attrs[1] = 0
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] = 0
        attrs[4] = speed
        attrs[5] = speed
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIOFLUSH)
        os.write(fd, b"\xc3" * 32)  # despertar
        time.sleep(0.2)
        os.write(fd, b"\x94\xc3\x00\x02\x18\x01")  # ToRadio{want_config_id: 1}
        buf = b""
        end = time.time() + 4
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.3)
            if r:
                try:
                    buf += os.read(fd, 4096)
                except BlockingIOError:
                    pass
        return buf
    finally:
        os.close(fd)


def valid_bind(v):
    if v == "tailscale":
        return True
    try:
        ipaddress.IPv4Address(v)
        return True
    except ValueError:
        return False


def bridge_run():
    cfg = load_config()
    b = cfg["bridge"]
    dev = b.get("device") or ""
    if not dev:
        sys.exit("meshtastic-bridge: no hay dispositivo serie configurado")
    bind = b.get("bind", "tailscale")
    ip = None
    if bind == "tailscale":
        for _ in range(60):
            ip = tailscale_ip()
            if ip:
                break
            time.sleep(2)
        if not ip:
            sys.exit("meshtastic-bridge: Tailscale no tiene IP todavía")
    else:
        ip = bind
    if not os.path.exists(dev):
        sys.exit("meshtastic-bridge: no existe %s" % dev)
    sc = shutil.which("socat") or "/usr/bin/socat"
    args = [sc, "-d", "TCP-LISTEN:%d,bind=%s,reuseaddr" % (int(b["port"]), ip),
            "%s,raw,echo=0,b%d" % (dev, int(b["baud"]))]
    print("meshtastic-bridge: %s" % " ".join(args), flush=True)
    os.execv(sc, args)


# --------------------------------------------------------------------------
# Rutas de la API
# --------------------------------------------------------------------------
def err(code, msg):
    return code, {"error": msg}


def api_login(req, ctx):
    ip = ctx["ip"]
    if too_many_fails(ip):
        return err(429, "Demasiados intentos. Espera unos minutos.")
    cfg = load_config()
    if not cfg.get("password"):
        return err(403, "Aún no hay credenciales. Ejecute en el equipo: sudo openstick-panel reset-credentials")
    user = str(req.get("username", "")).strip()
    pw = str(req.get("password", ""))
    ok_user = hmac.compare_digest(user.encode("utf-8"), str(cfg.get("username") or "admin").encode("utf-8"))
    ok_pw = check_pw(pw, cfg["password"])  # se evalúa siempre, para no revelar si el usuario existe
    if ok_user and ok_pw:
        ctx["set_cookie"] = new_session()
        return 200, {"ok": True}
    add_fail(ip)
    time.sleep(1)
    return err(401, "Usuario o contraseña incorrectos")


def api_logout(req, ctx):
    drop_session(ctx.get("token"))
    ctx["clear_cookie"] = True
    return 200, {"ok": True}


SCAN = {"done": False, "networks": [], "error": None, "at": 0}


def scan_networks(cfg):
    """Devuelve (redes, error)."""
    rc, out, e = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list",
                      "ifname", cfg["wifi_iface"], "--rescan", "yes"], timeout=30)
    if rc != 0:
        return [], (e or out).strip()[:300] or "No se pudo buscar redes"
    seen = {}
    for line in out.splitlines():
        p = split_terse(line)
        if len(p) < 5 or not p[1]:
            continue
        net = {"in_use": p[0].strip() == "*", "ssid": p[1], "signal": int(p[2] or 0),
               "chan": p[3], "security": p[4]}
        if p[1] not in seen or net["signal"] > seen[p[1]]["signal"]:
            seen[p[1]] = net
    return sorted(seen.values(), key=lambda n: -n["signal"]), None


def scan_job():
    """Con el punto de acceso encendido la antena no puede buscar: se apaga un momento,
    se busca y se vuelve a encender."""
    cfg = load_config()
    hot, ifc = cfg["hotspot_con"], cfg["wifi_iface"]
    SCAN.update(done=False, networks=[], error=None)
    jlog("Apagando el punto de acceso un momento para poder buscar redes…")
    run(["nmcli", "con", "down", "id", hot], timeout=20)
    time.sleep(3)
    nets, error = [], None
    for _ in range(3):
        nets, error = scan_networks(cfg)
        if nets:
            break
        time.sleep(3)
    jlog("Redes encontradas: %d" % len(nets))
    jlog("Reactivando el punto de acceso «%s»…" % hot)
    rc, out, e = run(["nmcli", "-w", "30", "con", "up", "id", hot], timeout=45)
    jlog("Punto de acceso " + ("encendido." if rc == 0 else "NO se pudo encender: " + (e or out).strip()[:200]))
    SCAN.update(done=True, networks=nets, error=error, at=time.time())
    return rc == 0


def api_wifi_scan(req, ctx):
    cfg = load_config()
    st = wifi_status(cfg)
    if st.get("is_hotspot"):
        if not start_job("Buscar redes WiFi", scan_job):
            return err(409, "Ya hay otra tarea en marcha")
        return 202, {"started": True}
    nets, error = scan_networks(cfg)
    if error:
        return err(500, error)
    return 200, {"networks": nets, "note": None}


def api_wifi_scanresult(req, ctx):
    return 200, dict(SCAN)


def api_wifi_saved(req, ctx):
    cfg = load_config()
    rc, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE,AUTOCONNECT", "con", "show"], timeout=8)
    res = []
    if rc == 0:
        for line in out.splitlines():
            p = split_terse(line)
            if len(p) >= 3 and p[1] in ("802-11-wireless", "wifi"):
                res.append({"name": p[0], "autoconnect": p[2] == "yes",
                            "hotspot": p[0] == cfg["hotspot_con"]})
    return 200, {"saved": res}


def api_wifi_connect(req, ctx):
    ssid = str(req.get("ssid", ""))
    pw = str(req.get("password", ""))
    if not ssid or len(ssid.encode("utf-8")) > 32 or "\x00" in ssid or ssid.startswith("-"):
        return err(400, "Nombre de red no válido")
    if pw and not (8 <= len(pw) <= 63):
        return err(400, "La clave WPA debe tener entre 8 y 63 caracteres")
    if "\x00" in pw:
        return err(400, "Clave no válida")
    if not start_job("Conectar a " + ssid, wifi_connect_job, ssid, pw):
        return err(409, "Ya hay otra tarea en marcha")
    return 202, {"started": True}


def api_wifi_forget(req, ctx):
    cfg = load_config()
    name = str(req.get("name", ""))
    if name not in saved_wifi_names():
        return err(404, "No es una red WiFi guardada")
    if name == cfg["hotspot_con"]:
        return err(400, "El punto de acceso no se puede borrar desde aquí")
    rc, out, e = run(["nmcli", "con", "delete", "id", name], timeout=15)
    if rc != 0:
        return err(500, (e or out).strip()[:300])
    return 200, {"ok": True}


def api_hotspot(req, ctx):
    on = bool(req.get("on"))
    if not start_job("Punto de acceso " + ("ON" if on else "OFF"), hotspot_job, on):
        return err(409, "Ya hay otra tarea en marcha")
    return 202, {"started": True}


APN_RE = re.compile(r"^[A-Za-z0-9._-]{0,64}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@-]{0,64}$")


def api_modem_apn(req, ctx):
    cfg = load_config()
    apn = str(req.get("apn", "")).strip()
    user = str(req.get("user", "")).strip()
    pw = str(req.get("password", ""))
    if not APN_RE.match(apn) or not USER_RE.match(user) or len(pw) > 64 or "\x00" in pw:
        return err(400, "APN, usuario o clave con caracteres no permitidos")
    cmd = ["nmcli", "con", "modify", "id", cfg["lte_con"], "gsm.apn", apn, "gsm.username", user]
    if "password" in req:
        cmd += ["gsm.password", pw]
    rc, out, e = run(cmd, timeout=15)
    if rc != 0:
        return err(500, (e or out).strip()[:300])
    # Lo que fijas a mano para esta SIM es lo que se recuerda
    m = modem_status(cfg)
    if m.get("iccid") and apn:
        cur = current_apn(cfg)
        remember_apn(cfg, m["iccid"], {"apn": apn, "user": user, "password": pw if "password" in req else cur.get("password", "")},
                     "puesto a mano")
    return 200, {"ok": True}


def api_modem_apns(req, ctx):
    cfg = load_config()
    m = modem_status(cfg)
    groups = detect_groups(m)
    saved = (cfg.get("apn_saved") or {}).get(m.get("iccid") or "")
    return 200, {
        "presets": [{"group": gg, "group_name": GROUP_NAMES.get(gg, gg), "label": l, "apn": a, "user": u, "password": pw}
                    for gg, l, a, u, pw in APN_PRESETS],
        "custom": cfg.get("apn_custom") or [],
        "detected": {"sim_operator": m.get("sim_operator"), "network": m.get("operator"),
                     "groups": groups, "group_names": [GROUP_NAMES.get(x, x) for x in groups]},
        "saved": {"apn": saved.get("apn"), "user": saved.get("user"), "label": saved.get("label")} if saved else None,
        "auto": bool(cfg.get("apn_auto", True)),
        "has_sim": bool(m.get("iccid")),
        "pin": {"auto": bool(cfg.get("pin_auto", True)),
                "saved": bool((cfg.get("pin_saved") or {}).get("last") or (cfg.get("pin_saved") or {}).get("by_iccid"))},
    }


def api_modem_apn_probe(req, ctx):
    if not start_job("Buscar APN", apn_probe_job, False):
        return err(409, "Ya hay otra tarea en marcha")
    return 202, {"started": True}


def api_modem_apn_auto(req, ctx):
    cfg = load_config()
    cfg["apn_auto"] = bool(req.get("on"))
    save_config(cfg)
    return 200, {"ok": True, "auto": cfg["apn_auto"]}


def api_modem_apn_custom(req, ctx):
    cfg = load_config()
    lst = cfg.get("apn_custom") or []
    if req.get("action") == "del":
        label = str(req.get("label", ""))
        lst = [c for c in lst if c.get("label") != label]
    elif req.get("action") == "add":
        label = str(req.get("label", "")).strip()[:40]
        apn = str(req.get("apn", "")).strip()
        user = str(req.get("user", "")).strip()
        pw = str(req.get("password", ""))
        if not label or not re.match(r"^[\w .()/+-]{1,40}$", label, re.UNICODE):
            return err(400, "Ponle un nombre sencillo (letras, números y espacios)")
        if not apn or not APN_RE.match(apn) or not USER_RE.match(user) or len(pw) > 64 or "\x00" in pw:
            return err(400, "APN, usuario o clave con caracteres no permitidos")
        if len(lst) >= 20 and not any(c.get("label") == label for c in lst):
            return err(400, "Ya hay 20 APN propios; borra alguno")
        lst = [c for c in lst if c.get("label") != label] + [{"label": label, "apn": apn, "user": user, "password": pw}]
    else:
        return err(400, "Acción desconocida")
    cfg["apn_custom"] = lst
    save_config(cfg)
    return 200, {"ok": True}


def api_modem_connect(req, ctx):
    on = bool(req.get("on"))
    if not start_job("Datos móviles " + ("ON" if on else "OFF"), lte_job, on, bool(req.get("restart"))):
        return err(409, "Ya hay otra tarea en marcha")
    return 202, {"started": True}


def api_modem_pin(req, ctx):
    pin = str(req.get("pin", ""))
    if not re.match(r"^\d{4,8}$", pin):
        return err(400, "El PIN debe tener entre 4 y 8 dígitos")
    st = modem_status(load_config())
    sim = st.get("sim") or ""
    m = re.search(r"(\d+)$", sim)
    if not m:
        return err(404, "No hay SIM detectada")
    rc, out, e = run(["mmcli", "-i", m.group(1), "--pin=" + pin], timeout=20)
    if rc != 0:
        return err(500, (e or out).strip()[:300])
    if req.get("remember", True):
        time.sleep(2)
        iccid = modem_status(load_config()).get("iccid")
        remember_pin(iccid, pin)
    return 200, {"ok": True}


def api_modem_pin_auto(req, ctx):
    cfg = load_config()
    cfg["pin_auto"] = bool(req.get("on"))
    save_config(cfg)
    return 200, {"ok": True, "auto": cfg["pin_auto"]}


def api_modem_pin_forget(req, ctx):
    forget_pin(everything=True)
    return 200, {"ok": True}


def api_tailscale(req, ctx):
    action = req.get("action")
    cmds = {
        "up": ["tailscale", "up"],
        "down": ["tailscale", "down"],
        "noroutes": ["tailscale", "set", "--accept-routes=false"],
    }
    if action not in cmds:
        return err(400, "Acción desconocida")
    rc, out, e = run(cmds[action], timeout=30)
    if rc != 0:
        return err(500, (e or out).strip()[:300])
    return 200, {"ok": True, "output": (out or e).strip()[:300]}


def api_bridge_get(req, ctx):
    return 200, bridge_info()


def api_bridge_config(req, ctx):
    cfg = load_config()
    b = cfg["bridge"]
    dev = str(req.get("device", "")).strip()
    try:
        baud = int(req.get("baud"))
        port = int(req.get("port"))
    except (TypeError, ValueError):
        return err(400, "Velocidad o puerto no válidos")
    bind = str(req.get("bind", "tailscale")).strip()
    if dev and not re.match(r"^/dev/tty[A-Za-z0-9_]+$", dev):
        return err(400, "El dispositivo debe ser algo como /dev/ttyMSM1")
    if baud not in BAUDS:
        return err(400, "Velocidad no admitida")
    if not (1024 <= port <= 65535):
        return err(400, "Puerto fuera de rango (1024-65535)")
    if not valid_bind(bind):
        return err(400, "Dirección de escucha no válida (usa «tailscale» o una IP)")
    b.update({"device": dev, "baud": baud, "port": port, "bind": bind})
    save_config(cfg)
    warn = None
    if bind == "0.0.0.0":
        warn = "Escuchar en 0.0.0.0 expone la API del nodo, sin cifrar, a toda la red."
    return 200, {"ok": True, "warning": warn}


def api_bridge_action(req, ctx):
    a = req.get("action")
    table = {
        "start": ["systemctl", "start", BRIDGE_UNIT],
        "stop": ["systemctl", "stop", BRIDGE_UNIT],
        "restart": ["systemctl", "restart", BRIDGE_UNIT],
        "enable": ["systemctl", "enable", BRIDGE_UNIT],
        "disable": ["systemctl", "disable", BRIDGE_UNIT],
    }
    if a not in table:
        return err(400, "Acción desconocida")
    if a in ("start", "restart", "enable") and not load_config()["bridge"]["device"]:
        return err(400, "Seleccione primero el dispositivo serie y guarde la configuración")
    rc, out, e = run(table[a], timeout=30)
    if rc != 0:
        return err(500, (e or out).strip()[:300])
    return 200, {"ok": True}


def api_bridge_probe(req, ctx):
    b = load_config()["bridge"]
    dev = b["device"]
    if not dev or not os.path.exists(dev):
        return err(400, "El dispositivo serie no existe todavía")
    was_active = svc_state(BRIDGE_UNIT)["active"] == "active"
    if was_active:
        run(["systemctl", "stop", BRIDGE_UNIT], timeout=20)
        time.sleep(1)
    try:
        buf = probe_serial(dev, int(b["baud"]))
    except Exception as e:  # noqa: BLE001
        if was_active:
            run(["systemctl", "start", BRIDGE_UNIT], timeout=20)
        return err(500, "No se pudo abrir el puerto: %s" % e)
    if was_active:
        run(["systemctl", "start", BRIDGE_UNIT], timeout=20)
    return 200, {"bytes": len(buf), "responds": b"\x94\xc3" in buf}


def api_logs(req, ctx):
    unit = LOG_UNITS.get(req.get("unit", ""))
    if not unit:
        return err(400, "Registro desconocido")
    rc, out, e = run(["journalctl", "-u", unit, "-n", "80", "--no-pager", "-o", "short"], timeout=15)
    return 200, {"text": out if rc == 0 else (e or out)}


def api_system(req, ctx):
    a = req.get("action")
    if a == "reboot":
        threading.Timer(2, lambda: run(["systemctl", "reboot"])).start()
    elif a == "poweroff":
        threading.Timer(2, lambda: run(["systemctl", "poweroff"])).start()
    elif a == "restart_panel":
        threading.Timer(1, lambda: run(["systemctl", "restart", "openstick-panel"])).start()
    else:
        return err(400, "Acción desconocida")
    return 200, {"ok": True}


USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")


def api_panel_password(req, ctx):
    """Cambia el usuario y/o la contraseña del panel (exige la contraseña actual)."""
    cfg = load_config()
    old = str(req.get("old", ""))
    if not check_pw(old, cfg.get("password")):
        return err(403, "La contraseña actual no es correcta")
    new_pw = str(req.get("new", "") or "")
    new_user = str(req.get("username", "") or "").strip()
    if not new_pw and not new_user:
        return err(400, "Indique un nuevo usuario o una nueva contraseña")
    if new_user and not USERNAME_RE.match(new_user):
        return err(400, "El usuario debe tener entre 3 y 32 caracteres (letras, números, punto, guion o guion bajo)")
    if new_pw and not (5 <= len(new_pw) <= 128):
        return err(400, "La nueva contraseña debe tener entre 5 y 128 caracteres")
    if new_user:
        cfg["username"] = new_user
    if new_pw:
        cfg["password"] = make_pw(new_pw)
    final_pw = new_pw if new_pw else old
    cfg["default_creds"] = (cfg.get("username") == "admin" and final_pw == "admin")
    save_config(cfg)
    # Las demás sesiones abiertas dejan de ser válidas
    with SLOCK:
        for t in list(SESSIONS):
            if t != ctx.get("token"):
                SESSIONS.pop(t, None)
    return 200, {"ok": True, "username": cfg["username"]}


GET_ROUTES = {
    "/api/status": lambda r, c: (200, get_status()),
    "/api/wifi/scan": api_wifi_scan,
    "/api/wifi/scanresult": api_wifi_scanresult,
    "/api/wifi/saved": api_wifi_saved,
    "/api/modem/apns": api_modem_apns,
    "/api/bridge": api_bridge_get,
    "/api/job": lambda r, c: (200, dict(JOB)),
    "/api/logs": api_logs,
}
POST_ROUTES = {
    "/api/login": api_login,
    "/api/logout": api_logout,
    "/api/wifi/connect": api_wifi_connect,
    "/api/wifi/forget": api_wifi_forget,
    "/api/hotspot": api_hotspot,
    "/api/modem/apn": api_modem_apn,
    "/api/modem/apn-probe": api_modem_apn_probe,
    "/api/modem/apn-auto": api_modem_apn_auto,
    "/api/modem/apn-custom": api_modem_apn_custom,
    "/api/modem/connect": api_modem_connect,
    "/api/modem/pin": api_modem_pin,
    "/api/modem/pin-auto": api_modem_pin_auto,
    "/api/modem/pin-forget": api_modem_pin_forget,
    "/api/tailscale": api_tailscale,
    "/api/bridge/config": api_bridge_config,
    "/api/bridge/action": api_bridge_action,
    "/api/bridge/probe": api_bridge_probe,
    "/api/system": api_system,
    "/api/panel/password": api_panel_password,
}


# --------------------------------------------------------------------------
# Servidor HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "openstick-panel"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silencio
        pass

    def _token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "osp":
                return v
        return None

    def _send(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, routes, req):
        path = self.path.split("?", 1)[0]
        query = {}
        if "?" in self.path:
            from urllib.parse import parse_qs
            query = {k: v[0] for k, v in parse_qs(self.path.split("?", 1)[1]).items()}
        if self.command == "GET" and path == "/":
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(204, "")
        if path == "/manifest.json":
            return self._send(200, {"name": "OpenStick", "short_name": "OpenStick", "start_url": "/",
                                    "display": "standalone", "background_color": "#0f1419",
                                    "theme_color": "#0f1419"}, "application/manifest+json")
        fn = routes.get(path)
        if not fn:
            return self._send(404, {"error": "no encontrado"})
        tok = self._token()
        ctx = {"ip": self.client_address[0], "token": tok}
        if path != "/api/login" and not valid_session(tok):
            return self._send(401, {"error": "sesión no iniciada"})
        if self.command == "GET":
            req = query
        try:
            code, obj = fn(req, ctx)
        except Exception as e:  # noqa: BLE001
            code, obj = 500, {"error": "error interno: %s" % e}
        cookie = None
        if ctx.get("set_cookie"):
            cookie = "osp=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (ctx["set_cookie"], SESSION_TTL)
        elif ctx.get("clear_cookie"):
            cookie = "osp=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        self._send(code, obj, cookie=cookie)

    def do_GET(self):
        self._handle(GET_ROUTES, {})

    def do_POST(self):
        if self.headers.get("X-OSP") != "1":
            self.close_connection = True
            return self._send(403, {"error": "petición no permitida"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > 65536:
            self.close_connection = True
            return self._send(413, {"error": "petición demasiado grande"})
        raw = self.rfile.read(n) if n else b"{}"
        try:
            req = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(req, dict):
                raise ValueError
        except Exception:  # noqa: BLE001
            return self._send(400, {"error": "JSON no válido"})
        self._handle(POST_ROUTES, req)


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_address(addr, port):
    """Intenta escuchar en addr:port; reintenta si la IP aún no existe."""
    def loop():
        server = None
        while server is None:
            ip = tailscale_ip() if addr == "tailscale" else addr
            if ip:
                try:
                    server = QuietServer((ip, port), Handler)
                except OSError as e:
                    print("no puedo escuchar en %s:%d (%s); reintento" % (ip, port, e), flush=True)
            if server is None:
                time.sleep(10)
        print("panel escuchando en http://%s:%d" % server.server_address, flush=True)
        server.serve_forever()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def cmd_serve(argv):
    cfg = load_config()
    binds = cfg["bind"]
    port = int(cfg["port"])
    i = 0
    while i < len(argv):
        if argv[i] == "--bind" and i + 1 < len(argv):
            binds = [x for x in argv[i + 1].split(",") if x]
            i += 2
        elif argv[i] == "--port" and i + 1 < len(argv):
            port = int(argv[i + 1])
            i += 2
        else:
            i += 1
    if not cfg.get("password"):
        cmd_reset_credentials()
        cfg = load_config()
    threads = [serve_address(b, port) for b in binds]
    threading.Thread(target=apn_watch, daemon=True).start()
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def cmd_reset_credentials():
    cfg = load_config()
    cfg["username"] = "admin"
    cfg["password"] = make_pw("admin")
    cfg["default_creds"] = True
    save_config(cfg)
    print("Credenciales predeterminadas restablecidas: usuario «admin», contraseña «admin».")
    print("Se recomienda cambiarlas desde la pestaña Sistema del panel.")


def cmd_set_password():
    cfg = load_config()
    if sys.stdin.isatty():
        p1 = getpass.getpass("Nueva contraseña del panel (mínimo 5): ")
        p2 = getpass.getpass("Repítela: ")
    else:
        p1 = sys.stdin.readline().rstrip("\n")
        p2 = p1
    if p1 != p2:
        sys.exit("No coinciden.")
    if len(p1) < 5:
        sys.exit("Mínimo 5 caracteres.")
    cfg["password"] = make_pw(p1)
    cfg["default_creds"] = (cfg.get("username") == "admin" and p1 == "admin")
    save_config(cfg)
    print("Contraseña guardada.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "serve":
        cmd_serve(sys.argv[2:])
    elif cmd == "set-password":
        cmd_set_password()
    elif cmd == "reset-credentials":
        cmd_reset_credentials()
    elif cmd == "bridge-run":
        bridge_run()
    else:
        print(__doc__)


# --------------------------------------------------------------------------
# Interfaz web (una sola página)
# --------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f1419">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="OpenStick">
<link rel="manifest" href="/manifest.json">
<title>OpenStick</title>
<style>
:root{--bg:#0f1419;--card:#18202a;--line:#2a3542;--text:#e6edf3;--mut:#8b98a8;--acc:#3fb4a3;--bad:#e5534b;--warn:#d9a441;--ok:#3fb950}
@media (prefers-color-scheme:light){:root{--bg:#f4f6f8;--card:#fff;--line:#d9e0e7;--text:#17202a;--mut:#5b6b7b;--acc:#0e7c6e;--bad:#c4362e;--warn:#9a6a08;--ok:#1a7f37}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0;flex:1}
header small{color:var(--mut)}
nav{display:flex;gap:4px;padding:8px 12px;overflow-x:auto;border-bottom:1px solid var(--line)}
nav button{background:none;border:0;color:var(--mut);padding:8px 12px;border-radius:8px;font:inherit;cursor:pointer;white-space:nowrap}
nav button.on{background:var(--card);color:var(--text);box-shadow:inset 0 0 0 1px var(--line)}
main{padding:16px;max-width:980px;margin:0 auto}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.card h2{margin:0 0 8px;font-size:14px;color:var(--mut);font-weight:600;letter-spacing:.03em;text-transform:uppercase}
.row{display:flex;justify-content:space-between;gap:12px;padding:3px 0}
.row span:first-child{color:var(--mut)}
.row span:last-child{text-align:right;word-break:break-word}
label{display:block;font-size:13px;color:var(--mut);margin:10px 0 4px}
input,select{width:100%;padding:10px 12px;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:8px;font:inherit;font-size:16px;min-height:44px}
button.b{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 16px;min-height:44px;font:inherit;cursor:pointer;margin:8px 8px 0 0;touch-action:manipulation}
button.b.sec{background:none;color:var(--text);border:1px solid var(--line)}
button.b.red{background:var(--bad)}
button.b:disabled{opacity:.5;cursor:default}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.mut{color:var(--mut)}
.t-ok{--c:var(--ok)}.t-warn{--c:var(--warn)}.t-bad{--c:var(--bad)}.t-off{--c:var(--mut)}.t-info{--c:#4c8dff}
.ic{flex:0 0 auto;width:34px;height:34px;border-radius:50%;background:color-mix(in srgb,var(--c) 18%,transparent);color:var(--c);display:grid;place-items:center;font-weight:800;font-size:18px;line-height:1}
.hero{display:flex;gap:14px;align-items:center;padding:16px;border-radius:14px;border:1px solid var(--c);background:color-mix(in srgb,var(--c) 10%,var(--card));margin-bottom:12px}
.hero .ic{width:48px;height:48px;font-size:26px}
.hero b{display:block;font-size:20px;color:var(--c)}
.hero span{display:block;color:var(--mut);font-size:14px}
.hero small{margin-left:auto;color:var(--mut);font-size:12px;white-space:nowrap;align-self:flex-start}
.tiles{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:12px}
.tile{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--c);border-radius:12px;padding:12px;min-height:112px;display:flex;flex-direction:column;gap:3px}
.tile .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.tile .k{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.tile .v{font-size:19px;font-weight:700;color:var(--c);line-height:1.2;margin-top:4px}
.tile .s{font-size:13px;color:var(--mut);word-break:break-word}
.tile .ic{width:28px;height:28px;font-size:15px}
.probs{margin-bottom:12px}
.prob{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border-radius:10px;border:1px solid var(--c);background:color-mix(in srgb,var(--c) 9%,var(--card));margin-bottom:8px}
.prob .ic{width:26px;height:26px;font-size:14px}
.prob p{margin:0;flex:1;font-size:14px}
.prob button.b{margin:0;min-height:36px;padding:6px 12px}
details.det{margin-top:4px}
details.det>summary{cursor:pointer;color:var(--mut);padding:10px 2px;font-size:14px;min-height:44px;display:flex;align-items:center}
details.det[open]>summary{margin-bottom:6px}
.msg{padding:10px 12px;border-radius:8px;border:1px solid var(--line);margin:0 0 12px}
.msg.warn{border-color:var(--warn)}.msg.bad{border-color:var(--bad)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:320px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.net{display:flex;align-items:center;gap:10px;padding:14px 4px;min-height:48px;border-bottom:1px solid var(--line);cursor:pointer}
.net:last-child{border:0}.net b{flex:1}
.bars{letter-spacing:1px;color:var(--acc)}
#login{max-width:340px;margin:12vh auto;padding:0 16px}
#toast{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:var(--card);border:1px solid var(--line);padding:10px 16px;border-radius:10px;display:none;max-width:90vw;z-index:9}
code{background:var(--bg);padding:1px 5px;border-radius:5px;border:1px solid var(--line)}
header{padding-top:calc(12px + env(safe-area-inset-top))}
@media (max-width:640px){
nav{position:fixed;bottom:0;left:0;right:0;z-index:6;background:var(--card);border-top:1px solid var(--line);border-bottom:0;padding:6px 6px calc(6px + env(safe-area-inset-bottom));gap:2px}
nav button{flex:1;min-width:0;min-height:44px;padding:10px 4px;font-size:13px;text-align:center}
main{padding:12px 12px calc(84px + env(safe-area-inset-bottom))}
header{padding-left:12px;padding-right:12px}
.grid{grid-template-columns:1fr}
.tiles{grid-template-columns:1fr 1fr}
.tiles .tile:last-child:nth-child(odd){grid-column:1/-1;min-height:0}
.tile .v{font-size:17px}
.hero{padding:14px}
.hero small{display:none}
#toast{bottom:calc(84px + env(safe-area-inset-bottom))}
button.b{flex:0 0 auto}
}
</style>
</head>
<body>
<div id="app" hidden>
<header><h1>OpenStick <small id="host"></small></h1><button class="b sec" id="logout" style="margin:0">Salir</button></header>
<nav id="tabs"></nav>
<main><div id="job"></div><div id="view"></div></main>
</div>
<form id="login" hidden autocomplete="on">
<h1>OpenStick</h1>
<p class="mut">Panel de control del equipo.</p>
<label for="user">Usuario</label>
<input id="user" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false">
<label for="pw">Contraseña</label>
<input id="pw" name="password" type="password" autocomplete="current-password">
<button class="b" id="go" type="submit">Entrar</button>
<p id="lerr" class="bad"></p>
</form>
<div id="toast"></div>
<script>
const $=s=>document.querySelector(s);
function h(tag,attrs,...kids){const e=document.createElement(tag);for(const[k,v]of Object.entries(attrs||{})){if(k==='class')e.className=v;else if(k.startsWith('on'))e.addEventListener(k.slice(2),v);else if(v!==false&&v!=null)e.setAttribute(k,v===true?'':v)}for(const c of kids.flat()){if(c==null||c===false)continue;e.append(c&&c.nodeType?c:document.createTextNode(String(c)))}return e}
async function api(path,body){
  const opt=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-OSP':'1'},body:JSON.stringify(body)};
  const r=await fetch(path,opt);
  if(r.status===401&&path!=='/api/login'){showLogin();throw new Error('sesión caducada')}
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(j.error||('Error '+r.status));
  return j;
}
function toast(m,bad){const t=$('#toast');t.textContent=m;t.style.borderColor=bad?'var(--bad)':'var(--line)';t.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(()=>t.style.display='none',4500)}
async function act(fn,okMsg){try{const r=await fn();if(okMsg)toast(okMsg);return r}catch(e){toast(e.message,true)}}
function fmtUp(s){if(s==null)return '—';const d=Math.floor(s/86400),hh=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+' d ':'')+hh+' h '+m+' min'}
function row(k,v){return h('div',{class:'row'},h('span',{},k),h('span',{},v==null||v===''?'—':v))}
function card(title,...kids){return h('div',{class:'card'},h('h2',{},title),...kids)}
function bars(p){p=+p||0;const n=Math.round(p/25);return '▂▄▆█'.slice(0,n)||'·'}
const ES={active:'activo',inactive:'parado',failed:'con error',activating:'arrancando',enabled:'sí',disabled:'no',Running:'conectado',registered:'registrado',home:'registrado',connected:'conectado'};
function stateTxt(s){const ok=s==='active'||s==='connected'||s==='registered'||s==='Running';return h('span',{class:ok?'ok':(s==='failed'?'bad':'mut')},ES[s]||s||'—')}
function yn(s){return ES[s]||s||'—'}

let TAB='estado',timer=null,JOBT=null;
const TABS=[['estado','Estado'],['wifi','WiFi'],['sim','SIM'],['nodo','Nodo'],['sistema','Sistema']];
function drawTabs(){const n=$('#tabs');n.replaceChildren(...TABS.map(([k,l])=>h('button',{class:k===TAB?'on':'',onclick:()=>{TAB=k;drawTabs();render()}},l)))}
function lsGet(k){try{return localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function showLogin(){$('#app').hidden=true;$('#login').hidden=false;if(!$('#user').value)$('#user').value=lsGet('osp-user')||'admin';$('#pw').focus()}
function showApp(){$('#login').hidden=true;$('#app').hidden=false;drawTabs();render()}
$('#login').addEventListener('submit',e=>{e.preventDefault();doLogin()});
async function doLogin(){$('#lerr').textContent='';try{const u=$('#user').value.trim();await api('/api/login',{username:u,password:$('#pw').value});lsSet('osp-user',u);$('#pw').value='';showApp()}catch(e){$('#lerr').textContent=e.message}}
$('#logout').onclick=async()=>{try{await api('/api/logout',{})}catch(e){}showLogin()};

let VIEW=null;
function render(){clearInterval(timer);
  /* cada pantalla escribe en su propio contenedor: si cambias de pestaña, lo que llega tarde se descarta */
  const v=h('div',{});VIEW=v;$('#view').replaceChildren(v);v.replaceChildren(h('p',{class:'mut'},'Cargando…'));
  ({estado:rEstado,wifi:rWifi,sim:rSim,nodo:rNodo,sistema:rSistema})[TAB]().catch(e=>{if(e.message!=='sesión caducada')v.replaceChildren(h('div',{class:'msg bad'},e.message))});
}

/* ---------- tareas ---------- */
function watchJob(){clearInterval(JOBT);const tick=async()=>{try{const j=await api('/api/job');const box=$('#job');
  if(!j.name){box.replaceChildren();return}
  box.replaceChildren(h('div',{class:'msg '+(j.running?'warn':j.ok?'':'bad')},h('b',{},j.name+(j.running?' …':j.ok?' ✓':' ✗')),h('pre',{},j.log.join('\n')),
    j.running?null:h('button',{class:'b sec',onclick:()=>{$('#job').replaceChildren();if(TAB!=='nodo')render()}},'Cerrar')));
  if(!j.running){clearInterval(JOBT)}}catch(e){}};tick();JOBT=setInterval(tick,1500)}

/* ---------- Diagnóstico: semáforos y problemas ---------- */
const ICON={ok:'✓',warn:'!',bad:'✕',off:'–',info:'i'};
const VIA={wwan0:'4G',wlan0:'WiFi',br0:'USB',usb0:'USB',tailscale0:'Tailscale'};
function diag(s){
  const T=[],P=[];const prob=(tone,text,btn,fn)=>P.push({tone,text,btn,fn});
  const w=s.wifi||{},m=s.modem||{},t=s.tailscale||{},b=s.bridge||{},sy=s.system||{},net=s.internet||{};
  const via=VIA[net.via]||net.via||'';
  /* Internet */
  const PN={wifi:'WiFi','4g':'4G'},paths=Object.entries(net.paths||{});
  const okNames=paths.filter(([,p])=>p.ok).map(([k])=>PN[k]||k);
  const badNames=paths.filter(([,p])=>!p.ok).map(([k])=>PN[k]||k);
  const viaTxt=okNames.length?okNames.join(' y '):via;
  if(net.ok){const wBad=paths.some(([k,p])=>!p.ok&&k==='wifi'),gBad=paths.some(([k,p])=>!p.ok&&k==='4g')&&!!m.lte_active,partial=wBad||gBad;
    T.push({k:'Internet',tone:partial?'warn':'ok',v:'Con internet',s:paths.length?paths.map(([k,p])=>(PN[k]||k)+(p.ok?' ✓':' ✕')).join(' · '):(via?'Sale por '+via:'Funciona')});
    if(wBad)prob('warn','El WiFi está conectado pero no tiene salida a internet.');
    if(gBad)prob('warn','Los datos 4G están conectados pero no tienen salida a internet.')}
  else{T.push({k:'Internet',tone:'bad',v:'Sin internet',s:'No hay salida a la red'});
    prob('bad','El equipo no tiene acceso a internet. Verifique la SIM y los datos móviles, o conéctelo a una red WiFi.')}
  /* WiFi */
  const sig=w.signal!=null?+w.signal:null;
  if(w.is_hotspot)T.push({k:'WiFi',tone:'info',v:'Punto de acceso',s:'Emite su propia red'+(w.ssid?' «'+w.ssid+'»':'')});
  else if(w.connection&&w.ip){const weak=sig!=null&&sig<30;
    T.push({k:'WiFi',tone:weak?'warn':'ok',v:'Conectado',s:[w.ssid||w.connection,sig!=null?sig+'% '+bars(sig):null].filter(Boolean).join(' · ')});
    if(weak)prob('warn','Señal WiFi débil ('+sig+'%). Se recomienda acercar el equipo al router.')}
  else if(w.connection){T.push({k:'WiFi',tone:'warn',v:'Sin IP',s:'Conectando a «'+w.connection+'»…'});
    prob('warn','El WiFi «'+w.connection+'» no ha dado dirección IP todavía.')}
  else T.push({k:'WiFi',tone:'off',v:'Sin WiFi',s:'No está en ninguna red'});
  /* SIM / datos móviles */
  const lock=m.state==='locked'||/^(sim-pin|sim-puk|ph-[a-z-]+|network-[a-z-]+)$/.test(m.unlock||'');
  const sigm=m.signal!=null?+m.signal:null;
  const simOk=m.sim&&m.sim!=='--';
  if(!m.present){T.push({k:'SIM · 4G',tone:'bad',v:'Sin módem',s:m.error||'No se detecta el módem'});
    prob('bad','No se detecta el módem. Reinicie el equipo; si persiste, puede tratarse de un fallo de hardware.')}
  else if(!simOk){T.push({k:'SIM · 4G',tone:'bad',v:'Sin SIM',s:'No se detecta la tarjeta'});
    prob('bad','No se detecta la SIM. Apague el equipo y verifique que está correctamente insertada.')}
  else if(lock){T.push({k:'SIM · 4G',tone:'bad',v:'Pide PIN',s:'Introducir en la pestaña SIM'});
    prob('bad','La SIM está bloqueada y pide PIN.','Ir a SIM',()=>{TAB='sim';drawTabs();render()})}
  else if(m.lte_active&&m.state==='connected'){const weak=sigm!=null&&sigm<25;
    T.push({k:'SIM · 4G',tone:weak?'warn':'ok',v:'Datos conectados',s:[m.operator,(m.tech||[]).join('/').toUpperCase(),sigm!=null?sigm+'% '+bars(sigm):null].filter(Boolean).join(' · ')});
    if(weak)prob('warn','Cobertura móvil baja ('+sigm+'%). Se recomienda cambiar la ubicación del equipo.')}
  else if(m.state==='registered'||m.state==='connected'){T.push({k:'SIM · 4G',tone:'warn',v:'Sin datos',s:'Registrada en '+(m.operator||'la red')+', datos apagados'});
    prob('warn','Hay cobertura, pero los datos móviles no están conectados. Verifique el APN o utilice «Conectar».','Conectar',()=>act(()=>api('/api/modem/connect',{on:true})).then(r=>{if(r)watchJob()}))}
  else if(m.state==='failed'){T.push({k:'SIM · 4G',tone:'bad',v:'Error del módem',s:'Estado: failed'});prob('bad','El módem presenta un error. Reinicie el equipo.')}
  else{T.push({k:'SIM · 4G',tone:'warn',v:'Buscando red',s:'Estado: '+yn(m.state)});prob('warn','El módem todavía no se ha registrado en la red móvil.')}
  /* Tailscale */
  if(t.installed===false){T.push({k:'Tailscale',tone:'bad',v:'No instalado',s:''});prob('bad','Tailscale no está instalado.')}
  else if(t.state==='Running')T.push({k:'Tailscale',tone:'ok',v:'Conectado',s:[(t.ips||[])[0],t.peers!=null?t.peers_online+' de '+t.peers+' en línea':null].filter(Boolean).join(' · ')});
  else if(t.state==='Starting')T.push({k:'Tailscale',tone:'warn',v:'Conectando',s:'Arrancando…'});
  else{T.push({k:'Tailscale',tone:'bad',v:t.state==='NeedsLogin'?'Sin sesión':(t.state==='Stopped'?'Apagado':'Sin conexión'),s:net.ok?'Sin acceso desde fuera':'Esperando internet'});
    prob('bad',net.ok?'Tailscale no está conectado: no habrá acceso remoto al equipo. Utilice «Encender» o revise la sesión.':'Tailscale está a la espera de conexión a internet.',net.ok&&t.state==='Stopped'?'Encender':null,()=>act(()=>api('/api/tailscale',{action:'up'}),'Tailscale encendido').then(render))}
  if(t.accept_routes)prob('warn','«Aceptar rutas» de Tailscale está activado y puede romper el acceso por la red local.','Desactivar',()=>act(()=>api('/api/tailscale',{action:'noroutes'}),'Desactivado').then(render));
  /* Nodo Meshtastic */
  const cf=b.config||{},svOn=b.service&&b.service.active==='active';
  if(!cf.device)T.push({k:'Nodo',tone:'off',v:'Sin configurar',s:'Seleccione el puerto serie'});
  else if(!b.device_exists){T.push({k:'Nodo',tone:'bad',v:'Sin puerto serie',s:cf.device+' no existe'});
    prob('bad','El puerto serie del nodo ('+cf.device+') no existe. Verifique el cable y el dispositivo en la pestaña Nodo.','Ir a Nodo',()=>{TAB='nodo';drawTabs();render()})}
  else if(!svOn){T.push({k:'Nodo',tone:'warn',v:'Puente parado',s:'Iniciar desde la pestaña Nodo'});prob('warn','El puente del nodo está parado.','Iniciar',()=>act(()=>api('/api/bridge/action',{action:'start'}),'Arrancado').then(render))}
  else T.push({k:'Nodo',tone:'ok',v:'Puente activo',s:(b.clients||0)+' cliente'+(b.clients===1?'':'s')+' · puerto '+cf.port});
  if(s.auth&&s.auth.default_creds)prob('warn','Se están utilizando las credenciales predeterminadas (admin / admin). Se recomienda cambiarlas.','Cambiar',()=>{TAB='sistema';drawTabs();render()});
  /* Sistema */
  if(sy.temp_c!=null&&sy.temp_c>=85)prob('bad','Temperatura crítica ('+sy.temp_c+' °C). Se recomienda ubicar el equipo en un lugar ventilado.');
  else if(sy.temp_c!=null&&sy.temp_c>=75)prob('warn','Temperatura elevada ('+sy.temp_c+' °C).');
  if(sy.mem_avail_mb!=null&&sy.mem_avail_mb<40)prob('warn','Memoria libre baja ('+sy.mem_avail_mb+' MB).');
  if(sy.disk_free_gb!=null&&sy.disk_free_gb<0.3)prob('warn','Espacio libre en disco bajo ('+sy.disk_free_gb+' GB).');
  return {T,P,via,net,viaTxt};
}
let DET_OPEN=null;
function heroTone(P){return P.some(p=>p.tone==='bad')?'bad':P.length?'warn':'ok'}

/* ---------- Estado ---------- */
async function rEstado(){
  const v=VIEW;
  const draw=async()=>{const s=await api('/api/status');if(!v.isConnected)return;$('#host').textContent=s.system.hostname||'';
    const d=diag(s),tone=heroTone(d.P);
    const nb=d.P.filter(p=>p.tone==='bad').length;
    const hero=h('div',{class:'hero t-'+tone},h('div',{class:'ic'},ICON[tone]),
      h('div',{},h('b',{},tone==='ok'?'Todo en orden':(nb?(d.P.length===1?'Hay 1 problema':'Hay '+d.P.length+' problemas'):(d.P.length===1?'1 aviso':d.P.length+' avisos'))),
        h('span',{},tone==='ok'?(d.net.ok?'Con internet'+(d.viaTxt?' por '+d.viaTxt:''):''):'Los detalles están debajo')),
      h('small',{},new Date().toLocaleTimeString('es-ES')));
    const tiles=h('div',{class:'tiles'},...d.T.map(x=>h('div',{class:'tile t-'+x.tone},h('div',{class:'top'},h('span',{class:'k'},x.k),h('span',{class:'ic'},ICON[x.tone])),h('div',{class:'v'},x.v),h('div',{class:'s'},x.s||''))));
    const probs=d.P.length?h('div',{class:'probs'},...d.P.map(p=>h('div',{class:'prob t-'+p.tone},h('span',{class:'ic'},ICON[p.tone]),h('p',{},p.text),p.btn?h('button',{class:'b sec',onclick:p.fn},p.btn):null))):null;
    const sy=s.system,w=s.wifi,t=s.tailscale,m=s.modem,b=s.bridge;const cards=[];
    cards.push(card('Sistema',row('Tiempo encendido',fmtUp(sy.uptime_s)),row('Memoria libre',sy.mem_avail_mb!=null?sy.mem_avail_mb+' / '+sy.mem_total_mb+' MB':null),
      row('Disco libre',sy.disk_free_gb!=null?sy.disk_free_gb+' / '+sy.disk_total_gb+' GB':null),row('Temperatura',sy.temp_c!=null?sy.temp_c+' °C':null),row('Kernel',sy.kernel)));
    cards.push(card('WiFi',row('Conexión',w.connection),row('Modo',w.is_hotspot?'Punto de acceso':(w.connection?'Cliente':'—')),row('Red',w.ssid),...(w.is_hotspot?[]:[row('Señal',w.signal!=null?w.signal+'% '+bars(w.signal):null)]),row('IP',w.ip)));
    cards.push(card('Tailscale',row('Estado',t.installed===false?'no instalado':yn(t.state)),row('Nombre',t.name),row('IP',(t.ips||[])[0]),row('Equipos en línea',t.peers!=null?t.peers_online+' de '+t.peers:null)));
    cards.push(card('Módem / SIM',...(m.present?[row('Estado',yn(m.state)),row('Operador',m.operator),row('Red',(m.tech||[]).join(', ')),row('Señal',m.signal!=null?m.signal+'% '+bars(m.signal):null),row('SIM',m.sim&&m.sim!=='--'?'detectada':'no detectada'),row('APN',m.apn),row('Datos',m.lte_active?'conectados':'no conectados')]:[h('p',{class:'mut'},m.error||'No se detecta el módem.')])));
    cards.push(card('Puente Meshtastic',row('Servicio',stateTxt(b.service.active)),row('Arranque automático',yn(b.service.enabled)),row('Dispositivo',b.config.device||'sin elegir'),row('Dirección',(b.config.bind==='tailscale'?(b.tailscale_ip||'tailscale (sin IP)'):b.config.bind)+':'+b.config.port),row('Clientes conectados',b.clients)));
    cards.push(card('Red',...s.net.map(n=>row(n.name+' ('+(n.state||'?').toLowerCase()+')',n.addrs.join(', ')||'—'))));
    const det=h('details',{class:'det'},h('summary',{},'Detalles técnicos'),h('div',{class:'grid'},...cards));
    if(DET_OPEN===null)DET_OPEN=window.innerWidth>640;
    if(DET_OPEN)det.open=true;det.addEventListener('toggle',()=>{DET_OPEN=det.open});
    v.replaceChildren(hero,tiles,...(probs?[probs]:[]),det)};
  await draw();if(!v.isConnected)return;
  const t=setInterval(()=>{if(!v.isConnected){clearInterval(t);return}draw().catch(()=>{})},10000);timer=t;
}

/* ---------- WiFi ---------- */
async function rWifi(){
  const v=VIEW;const st=(await api('/api/status')).wifi;const saved=(await api('/api/wifi/saved')).saved;
  const list=h('div',{});const form=h('div',{});
  const cur=card('Conexión actual',row('Conexión',st.connection),row('Modo',st.is_hotspot?'Punto de acceso':(st.connection?'Cliente':'—')),row('Red',st.ssid),row('IP',st.ip),
    h('div',{},h('button',{class:'b sec',onclick:()=>{if(confirm(st.is_hotspot?'Se desactivará el punto de acceso y se intentará conectar a una red guardada. ¿Continuar?':'Se activará el punto de acceso. El equipo dejará de estar conectado a la red WiFi actual y, si accede por ella, esta sesión se interrumpirá. ¿Continuar?'))act(()=>api('/api/hotspot',{on:!st.is_hotspot})).then(watchJob)}},st.is_hotspot?'Apagar punto de acceso':'Encender punto de acceso')));
  const showNets=r=>list.replaceChildren(...(r.networks.length?r.networks.map(n=>h('div',{class:'net',onclick:()=>pick(n)},h('b',{},n.ssid),h('span',{class:'mut'},n.security&&n.security!=='--'?n.security:'abierta'),h('span',{class:'mut'},'canal '+n.chan),h('span',{class:'bars'},bars(n.signal)))):[h('p',{class:'mut'},'No se ven redes.')]));
  const scan=card('Buscar redes',h('button',{class:'b',id:'scanb',onclick:async e=>{const btn=e.target;
    if(st.is_hotspot&&!confirm('El equipo está emitiendo su propia red WiFi y, con la antena en uso, no puede buscar redes. El punto de acceso se desactivará unos 15 segundos y se reactivará automáticamente. Si accede por WiFi, la conexión se interrumpirá brevemente (por USB no se ve afectada). ¿Continuar?'))return;
    btn.disabled=true;btn.textContent='Buscando…';
    try{const r=await api('/api/wifi/scan');
      if(r.started){list.replaceChildren(h('p',{class:'mut'},'Buscando… puede tardar hasta 30 segundos.'));
        let got=null;for(let i=0;i<45&&!got;i++){await new Promise(z=>setTimeout(z,2000));try{const s=await api('/api/wifi/scanresult');if(s.done)got=s}catch(x){}}
        if(!got)list.replaceChildren(h('p',{class:'bad'},'No se recibió el resultado. Recargue la página e inténtelo de nuevo.'));
        else if(got.error)list.replaceChildren(h('p',{class:'bad'},got.error));
        else showNets(got)}
      else showNets(r)}catch(x){list.replaceChildren(h('p',{class:'bad'},x.message))}
    btn.disabled=false;btn.textContent='Buscar redes'}},'Buscar redes'),h('p',{class:'mut'},'Este stick solo usa la banda de 2,4 GHz.'),list,form);
  function pick(n){const open=!n.security||n.security==='--';const pw=h('input',{type:'password',id:'wpw',autocomplete:'off'});
    form.replaceChildren(h('hr',{}),h('b',{},n.ssid),...(open?[]:[h('label',{},'Contraseña'),pw]),
      h('div',{class:'msg warn',style:'margin-top:10px'},'Si accede a este panel por WiFi, la conexión se interrumpirá durante el cambio de red. En caso de fallo, el equipo vuelve a la red anterior o al punto de acceso.'),
      h('button',{class:'b',onclick:()=>{if(!open&&pw.value.length<8){toast('La clave debe tener al menos 8 caracteres',true);return}act(()=>api('/api/wifi/connect',{ssid:n.ssid,password:open?'':pw.value})).then(r=>{if(r)watchJob()})}},'Conectar'),
      h('button',{class:'b sec',onclick:()=>form.replaceChildren()},'Cancelar'))}
  const sv=card('Redes guardadas',...(saved.length?saved.map(s=>h('div',{class:'row'},h('span',{style:'color:var(--text)'},s.name+(s.hotspot?' (punto de acceso)':'')),
    s.hotspot?h('span',{},''):h('button',{class:'b sec',style:'margin:0',onclick:()=>{if(confirm('¿Olvidar «'+s.name+'»?'))act(()=>api('/api/wifi/forget',{name:s.name}),'Olvidada').then(render)}},'Olvidar'))):[h('p',{class:'mut'},'Ninguna.')]));
  v.replaceChildren(h('div',{class:'grid'},cur,scan,sv));watchJob();
}

/* ---------- SIM ---------- */
async function rSim(){
  const v=VIEW;const m=(await api('/api/status')).modem;const A=await api('/api/modem/apns').catch(()=>null);
  const stc=card('Estado',...(m.present?[row('Módem',[m.manufacturer,m.model].filter(Boolean).join(' ')),row('Firmware',m.revision),row('IMEI',m.imei),row('Estado',m.state),row('Bloqueo',/^(sim-pin|sim-puk|ph-[a-z-]+|network-[a-z-]+)$/.test(m.unlock||'')?m.unlock:'ninguno'),row('Operador',m.operator),row('Registro',m.registration),row('Red',(m.tech||[]).join(', ')),row('Señal',m.signal!=null?m.signal+'% '+bars(m.signal):null),row('SIM',m.sim&&m.sim!=='--'?'detectada':'no detectada')]:[h('p',{class:'mut'},m.error||'No se detecta el módem.')]));
  const apn=h('input',{value:m.apn||'',placeholder:'p. ej. internet'}),usr=h('input',{value:m.apn_user||'',autocomplete:'off'}),pwd=h('input',{type:'password',autocomplete:'off',placeholder:'(sin cambios)'});
  let pwdTouched=false;pwd.addEventListener('input',()=>{pwdTouched=true});
  const ITEMS=[];const opt=(it,txt)=>{ITEMS.push(it);return h('option',{value:ITEMS.length-1},txt)};
  const sel=h('select',{},h('option',{value:''},'— Elegir un APN típico —'));
  if(A){const sug=new Set(A.detected.groups||[]);
    const sugPre=A.presets.filter(x=>sug.has(x.group));
    if(A.saved)sel.append(h('optgroup',{label:'Guardado para esta SIM'},opt({apn:A.saved.apn,user:A.saved.user||'',password:null},A.saved.apn+(A.saved.label?' ('+A.saved.label+')':''))));
    if(sugPre.length)sel.append(h('optgroup',{label:'Sugeridos para esta SIM ('+A.detected.group_names.join(', ')+')'},...sugPre.map(x=>opt(x,x.label+' · '+x.apn))));
    if(A.custom.length)sel.append(h('optgroup',{label:'APN personalizados'},...A.custom.map(x=>opt(x,x.label+' · '+x.apn))));
    const byG={};for(const x of A.presets)if(!sug.has(x.group))(byG[x.group_name]=byG[x.group_name]||[]).push(x);
    for(const [g,l] of Object.entries(byG))sel.append(h('optgroup',{label:g},...l.map(x=>opt(x,x.label+' · '+x.apn))));}
  sel.onchange=()=>{if(sel.value==='')return;const it=ITEMS[+sel.value];apn.value=it.apn;usr.value=it.user||'';if(it.password!=null){pwd.value=it.password;pwdTouched=true}};
  const body=()=>{const b={apn:apn.value.trim(),user:usr.value.trim()};if(pwdTouched||pwd.value)b.password=pwd.value;return b};
  const auto=h('input',{type:'checkbox',id:'apnauto',style:'width:auto;min-height:0;margin-right:8px'});auto.checked=A?A.auto:true;
  auto.onchange=()=>act(()=>api('/api/modem/apn-auto',{on:auto.checked}),auto.checked?'APN automático activado':'APN automático desactivado');
  const cfg=card('Datos móviles',row('Conexión',m.lte_active?'conectada':'desconectada'),
    ...(A?[row('SIM',[m.sim_operator,m.sim_code].filter(Boolean).join(' · ')||null),row('APN guardado',A.saved?A.saved.apn+(A.saved.label?' ('+A.saved.label+')':''):'ninguno')]:[]),
    h('button',{class:'b',onclick:()=>act(()=>api('/api/modem/apn-probe',{})).then(r=>{if(r)watchJob()})},'Detectar APN automáticamente'),
    h('p',{class:'mut',style:'margin:6px 0 0'},'Prueba de forma secuencial los APN habituales del operador hasta obtener acceso a internet y guarda el resultado para esta SIM.'),
    h('label',{style:'display:flex;align-items:center;margin-top:12px'},auto,'Seleccionar el APN automáticamente al cambiar de SIM'),
    h('hr',{}),h('b',{},'Configuración manual'),h('label',{},'APN típicos'),sel,h('label',{},'APN'),apn,h('label',{},'Usuario (opcional)'),usr,h('label',{},'Clave (opcional)'),pwd,
    h('div',{},
      h('button',{class:'b',onclick:async()=>{const r=await act(()=>api('/api/modem/apn',body()));if(r){const j=await act(()=>api('/api/modem/connect',{on:true,restart:true}));if(j)watchJob()}}},'Guardar y conectar'),
      h('button',{class:'b sec',onclick:()=>{const n=prompt('Nombre para este APN (p. ej. «Operador principal»)');if(!n)return;act(()=>api('/api/modem/apn-custom',{action:'add',label:n,...body(),password:pwd.value}),'Guardado en APN personalizados').then(render)}},'Guardar como personalizado'),
      h('button',{class:'b sec',onclick:()=>act(()=>api('/api/modem/connect',{on:!m.lte_active})).then(r=>{if(r)watchJob()})},m.lte_active?'Desconectar datos':'Conectar datos')),
    ...(A&&A.custom.length?[h('p',{class:'mut',style:'margin-top:10px'},'APN personalizados: ',...A.custom.map(x=>h('span',{class:'pill',style:'margin:2px 4px 2px 0;cursor:pointer',title:'Pulse para eliminar',onclick:()=>{if(confirm('¿Borrar «'+x.label+'»?'))act(()=>api('/api/modem/apn-custom',{action:'del',label:x.label}),'Borrado').then(render)}},x.label+' ✕')))]:[]));
  const pin=h('input',{type:'password',inputmode:'numeric',maxlength:'8',autocomplete:'off'});
  const rem=h('input',{type:'checkbox',style:'width:auto;min-height:0;margin-right:8px'});rem.checked=true;
  const pauto=h('input',{type:'checkbox',style:'width:auto;min-height:0;margin-right:8px'});pauto.checked=A?A.pin.auto:true;
  pauto.onchange=()=>act(()=>api('/api/modem/pin-auto',{on:pauto.checked}),pauto.checked?'Desbloqueo automático activado':'Desbloqueo automático desactivado');
  const pc=card('PIN de la SIM',h('p',{class:'mut'},'Solo es necesario si la SIM solicita PIN.'),h('label',{},'PIN'),pin,
    h('label',{style:'display:flex;align-items:center;margin-top:12px'},rem,'Guardar el PIN en el equipo'),
    h('button',{class:'b',onclick:()=>act(()=>api('/api/modem/pin',{pin:pin.value,remember:rem.checked}),'PIN enviado').then(()=>{pin.value='';setTimeout(render,2500)})},'Introducir PIN'),
    ...(A?[h('hr',{}),row('PIN guardado',A.pin.saved?'sí':'no'),
      h('label',{style:'display:flex;align-items:center'},pauto,'Desbloquear la SIM automáticamente al arrancar'),
      h('p',{class:'mut',style:'margin:6px 0 0'},'Se realiza un único intento automático por SIM y arranque, y solo si quedan los 3 intentos completos. Si el PIN guardado es rechazado, se elimina.'),
      ...(A.pin.saved?[h('button',{class:'b sec',onclick:()=>{if(confirm('¿Eliminar el PIN guardado?'))act(()=>api('/api/modem/pin-forget',{}),'PIN eliminado').then(render)}},'Eliminar PIN guardado')]:[])]:[]));
  v.replaceChildren(h('div',{class:'grid'},stc,cfg,pc));watchJob();
}

/* ---------- Nodo Meshtastic ---------- */
async function rNodo(){
  const v=VIEW;const b=await api('/api/bridge');const c=b.config;
  const devSel=h('select',{},h('option',{value:''},'— elige —'),...b.devices.map(d=>h('option',{value:d,selected:d===c.device},d)),h('option',{value:'__otro',selected:!!c.device&&!b.devices.includes(c.device)},'Otro…'));
  const devTxt=h('input',{placeholder:'/dev/ttyMSM1',value:b.devices.includes(c.device)?'':c.device,style:'margin-top:6px'});
  const baud=h('select',{},...b.bauds.map(x=>h('option',{value:x,selected:x===c.baud},x)));
  const port=h('input',{type:'number',value:c.port,min:1024,max:65535});
  const bind=h('input',{value:c.bind,placeholder:'tailscale o una IP'});
  const dev=()=>devSel.value==='__otro'||(!devSel.value&&devTxt.value)?devTxt.value.trim():devSel.value;
  const save=()=>act(async()=>{const r=await api('/api/bridge/config',{device:dev(),baud:+baud.value,port:+port.value,bind:bind.value.trim()});if(r.warning)toast(r.warning,true);return r},'Guardado');
  const svc=b.service;
  const info=card('Estado del puente',row('Servicio',stateTxt(svc.active)),row('Arranque automático',yn(svc.enabled)),row('Dispositivo serie',b.device_exists?'presente':(c.device?'no existe':'sin elegir')),row('Clientes conectados',b.clients),
    row('Dirección para conectar',(c.bind==='tailscale'?(b.tailscale_ip||'(Tailscale sin IP)'):c.bind)+':'+c.port),
    h('p',{class:'mut'},'Desde un equipo de la tailnet: ',h('code',{},'meshtastic --host '+(b.tailscale_ip||'IP_TAILSCALE')+' --info')),
    h('div',{},h('button',{class:'b',onclick:()=>act(()=>api('/api/bridge/action',{action:'start'}),'Arrancado').then(render)},'Iniciar'),
      h('button',{class:'b sec',onclick:()=>act(()=>api('/api/bridge/action',{action:'restart'}),'Reiniciado').then(render)},'Reiniciar'),
      h('button',{class:'b sec',onclick:()=>act(()=>api('/api/bridge/action',{action:'stop'}),'Parado').then(render)},'Parar')),
    h('div',{},h('button',{class:'b sec',onclick:()=>act(()=>api('/api/bridge/action',{action:svc.enabled==='enabled'?'disable':'enable'}),svc.enabled==='enabled'?'No arrancará solo':'Arrancará con el stick').then(render)},svc.enabled==='enabled'?'Quitar arranque automático':'Arrancar con el stick')),
    h('div',{},h('button',{class:'b sec',id:'probe',onclick:async e=>{e.target.disabled=true;e.target.textContent='Probando (unos segundos)…';
      try{const r=await api('/api/bridge/probe',{});toast(r.responds?'El nodo responde ('+r.bytes+' bytes)':(r.bytes?'Llegan datos ('+r.bytes+' bytes) pero no parecen de Meshtastic: revisa la velocidad':'Sin respuesta: revisa cables, TX/RX cruzados, velocidad y que el módulo Serial esté en modo PROTO'),!r.responds)}catch(x){toast(x.message,true)}
      e.target.disabled=false;e.target.textContent='Probar el nodo'}},'Probar el nodo')));
  const conf=card('Configuración',h('label',{},'Dispositivo serie'),devSel,devTxt,h('label',{},'Velocidad (baudios)'),baud,h('label',{},'Puerto TCP'),port,h('label',{},'Escuchar en'),bind,
    h('p',{class:'mut'},'«tailscale» usa la IP de Tailscale del stick. La API del nodo no va cifrada: no la abras a toda la red.'),
    h('p',{class:'mut'},'En el nodo: módulo Serial activado, modo PROTO, la misma velocidad y los pines RX/TX de la placa.'),
    h('button',{class:'b',onclick:()=>save().then(()=>render())},'Guardar'),
    h('button',{class:'b sec',onclick:async()=>{await save();act(()=>api('/api/bridge/action',{action:'restart'}),'Guardado y reiniciado').then(render)}},'Guardar y reiniciar'));
  const logs=card('Registro del puente',h('pre',{id:'blog'},'…'));
  v.replaceChildren(h('div',{class:'grid'},info,conf),h('div',{style:'margin-top:12px'},logs));
  api('/api/logs?unit=bridge').then(r=>{$('#blog').textContent=r.text||'(vacío)'}).catch(()=>{});
}

/* ---------- Sistema ---------- */
async function rSistema(){
  const v=VIEW;
  const sel=h('select',{},...[['panel','Este panel'],['bridge','Puente Meshtastic'],['tailscale','Tailscale'],['red','NetworkManager'],['modem','ModemManager']].map(([k,l])=>h('option',{value:k},l)));
  const pre=h('pre',{},'');const load=()=>api('/api/logs?unit='+sel.value).then(r=>{pre.textContent=r.text||'(vacío)'}).catch(e=>{pre.textContent=e.message});sel.onchange=load;load();
  const logs=card('Registros',sel,h('div',{style:'height:8px'}),pre,h('button',{class:'b sec',onclick:load},'Actualizar'));
  const S0=await api('/api/status');const ts=S0.tailscale;
  const tsc=card('Tailscale',row('Estado',ts.state),row('Aceptar rutas',ts.accept_routes==null?'—':(ts.accept_routes?'activado (no recomendado en el stick)':'desactivado')),
    h('button',{class:'b sec',onclick:()=>act(()=>api('/api/tailscale',{action:'noroutes'}),'Aceptar rutas desactivado').then(render)},'Desactivar aceptar rutas'),
    h('button',{class:'b sec',onclick:()=>{if(confirm('Si accede mediante Tailscale, la conexión se interrumpirá. ¿Continuar?'))act(()=>api('/api/tailscale',{action:'down'}),'Tailscale apagado')}},'Apagar Tailscale'),
    h('button',{class:'b sec',onclick:()=>act(()=>api('/api/tailscale',{action:'up'}),'Tailscale encendido').then(render)},'Encender Tailscale'));
  const cu=h('input',{value:S0.auth.user,autocomplete:'username',autocapitalize:'none',spellcheck:'false'}),o=h('input',{type:'password',autocomplete:'current-password'}),n=h('input',{type:'password',autocomplete:'new-password',placeholder:'(sin cambios)'});
  const pwc=card('Acceso al panel',row('Usuario actual',S0.auth.user),
    ...(S0.auth.default_creds?[h('div',{class:'msg warn',style:'margin-top:8px'},'Se están utilizando las credenciales predeterminadas (admin / admin). Se recomienda cambiarlas.')]:[]),
    h('label',{},'Usuario'),cu,h('label',{},'Contraseña actual'),o,h('label',{},'Nueva contraseña (opcional, mínimo 5 caracteres)'),n,
    h('button',{class:'b',onclick:()=>{const body={old:o.value,username:cu.value.trim()};if(n.value)body.new=n.value;act(()=>api('/api/panel/password',body),'Credenciales actualizadas').then(r=>{if(r){o.value='';n.value='';render()}})}},'Guardar cambios'),
    h('p',{class:'mut',style:'margin:8px 0 0'},'Al guardar se cierran las demás sesiones abiertas. Si olvida las credenciales, se restablecen en el equipo con: sudo openstick-panel reset-credentials'));
  const pw=card('Equipo',h('button',{class:'b sec',onclick:()=>{if(confirm('¿Reiniciar el stick?'))act(()=>api('/api/system',{action:'reboot'}),'Reiniciando…')}},'Reiniciar el stick'),
    h('button',{class:'b red',onclick:()=>{if(confirm('¿Apagar el equipo? Será necesario desconectarlo y volver a conectarlo para encenderlo.'))act(()=>api('/api/system',{action:'poweroff'}),'Apagando…')}},'Apagar'),
    h('button',{class:'b sec',onclick:()=>act(()=>api('/api/system',{action:'restart_panel'}),'Reiniciando el panel…')},'Reiniciar el panel'));
  v.replaceChildren(h('div',{class:'grid'},tsc,pwc,pw),h('div',{style:'margin-top:12px'},logs));
}

(async()=>{try{await api('/api/status');showApp()}catch(e){showLogin()}})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
