#!/bin/sh
# Instala el panel del stick OpenStick (Debian).
# Uso:  sudo sh install.sh
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Ejecuta con sudo:  sudo sh install.sh" >&2
  exit 1
fi

DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/openstick-panel.py" ] || { echo "Falta openstick-panel.py junto a este script" >&2; exit 1; }

echo "==> Instalando socat (para el puente serie-TCP)"
apt-get install -y socat >/dev/null

echo "==> Copiando el panel"
install -m 755 "$DIR/openstick-panel.py" /usr/local/bin/openstick-panel
mkdir -p /etc/openstick-panel
chmod 700 /etc/openstick-panel

echo "==> Creando los servicios"
cat > /etc/systemd/system/openstick-panel.service <<'EOF'
[Unit]
Description=Panel web del stick OpenStick
After=network.target NetworkManager.service tailscaled.service

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/openstick-panel serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/meshtastic-bridge.service <<'EOF'
[Unit]
Description=Puente Meshtastic serie a TCP (socat)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/openstick-panel bridge-run
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if ! grep -q '"hash"' /etc/openstick-panel/config.json 2>/dev/null; then
  echo
  echo "==> Credenciales iniciales del panel"
  /usr/bin/python3 /usr/local/bin/openstick-panel reset-credentials
fi

# Pasa un panel ya instalado al puerto 80 y añade la IP del USB
/usr/bin/python3 -I - <<'PYEOF'
import json, os
p = "/etc/openstick-panel/config.json"
if os.path.exists(p):
    c = json.load(open(p))
    c["port"] = 80
    b = c.get("bind") or []
    for a in ("tailscale", "192.168.100.1", "192.168.101.1"):
        if a not in b:
            b.append(a)
    c["bind"] = b
    json.dump(c, open(p, "w"), indent=2)
    os.chmod(p, 0o600)
PYEOF

systemctl enable --now openstick-panel
systemctl restart openstick-panel

echo
echo "Listo. El panel escucha en:"
TS=$(tailscale ip -4 2>/dev/null | head -n1 || true)
[ -n "$TS" ] && echo "  http://$TS   (por Tailscale)"
echo "  http://192.168.100.1   (conectado al WiFi del propio stick)"
echo "  http://192.168.101.1   (por el cable USB)"
echo
echo "Acceso al panel: usuario y contraseña (predeterminados: admin / admin; se cambian en la pestaña Sistema)."
echo "El puente Meshtastic no arranca solo: se configura desde la pestaña «Nodo Meshtastic»."
