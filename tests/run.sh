#!/bin/sh
# Ejecuta las pruebas de la API con comandos simulados (nmcli, mmcli, tailscale, ip…).
# No modifica el sistema: usa un directorio temporal y escucha solo en 127.0.0.1:18080.
set -e
cd "$(dirname "$0")"
TMP=$(mktemp -d)
PID=""
trap '[ -n "$PID" ] && kill $PID 2>/dev/null; rm -rf "$TMP"' EXIT INT TERM
export PATH="$PWD/bin:$PATH"
export OSP_CONFIG="$TMP/config.json"

nueva_config() {
  rm -f "$OSP_CONFIG"
  python3 -I - <<'PY'
import importlib.util, json, os
spec = importlib.util.spec_from_file_location("panel", "../openstick-panel.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
cfg = m.load_config()
cfg["password"] = m.make_pw("clave-de-prueba-1")
cfg["bridge"]["device"] = "/dev/ttyMSM1"
m.save_config(cfg)
PY
}

ejecutar() {
  nueva_config
  python3 -I ../openstick-panel.py serve --bind 127.0.0.1 --port 18080 >"$TMP/server.log" 2>&1 &
  PID=$!
  sleep 2
  python3 "$1"
  kill $PID 2>/dev/null || true
  wait $PID 2>/dev/null || true
  PID=""
}

ejecutar test_apn.py
ejecutar test_api.py
echo "Todas las pruebas han pasado."
