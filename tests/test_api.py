import http.client, json, time
H="127.0.0.1"; P=18080
cookie=None
def call(method,path,body=None,hdr=True,ck=True):
    c=http.client.HTTPConnection(H,P,timeout=40)
    h={}
    if body is not None: h["Content-Type"]="application/json"
    if hdr and method=="POST": h["X-OSP"]="1"
    if ck and cookie: h["Cookie"]="osp="+cookie
    c.request(method,path,json.dumps(body) if body is not None else None,h)
    r=c.getresponse(); data=r.read().decode()
    sc=r.getheader("Set-Cookie")
    try: j=json.loads(data)
    except Exception: j=data
    return r.status,j,sc
def chk(name,cond,extra=""):
    print(("OK   " if cond else "FALLA"),name,extra)
    if not cond: raise SystemExit(1)

s,j,_=call("GET","/"); chk("GET / sin sesión devuelve HTML",s==200 and "OpenStick" in j)
s,j,_=call("GET","/api/status"); chk("status sin sesión = 401",s==401)
s,j,_=call("POST","/api/login",{"username":"admin","password":"x"},hdr=False); chk("POST sin X-OSP = 403",s==403)
s,j,_=call("POST","/api/login",{"username":"admin","password":"mala"}); chk("login incorrecto = 401",s==401,j)
s,j,sc=call("POST","/api/login",{"username":"admin","password":"clave-de-prueba-1"}); chk("login correcto",s==200 and sc and "HttpOnly" in sc and "SameSite=Strict" in sc,sc)
cookie=sc.split(";")[0].split("=",1)[1]
s,j,_=call("GET","/api/status"); chk("status con sesión",s==200 and j["tailscale"]["state"]=="Running",)
print("   modem:",j["modem"]["state"],j["modem"]["operator"],j["modem"]["apn"],"| wifi:",j["wifi"]["ssid"],j["wifi"]["ip"],"| ts accept_routes:",j["tailscale"]["accept_routes"])
chk("módem leído",j["modem"]["present"] and j["modem"]["signal"]=="72")
chk("ifaces",any(n["name"]=="wlan0" for n in j["net"]))
chk("clientes del puente",j["bridge"]["clients"]==1)
s,j,_=call("GET","/api/wifi/scan"); chk("scan",s==200 and len(j["networks"])==4,[n["ssid"] for n in j["networks"]])
chk("SSID con ':' bien separado",any(n["ssid"]=="Mi:Red con dos puntos" for n in j["networks"]))
s,j,_=call("GET","/api/wifi/saved"); chk("guardadas",s==200 and len(j["saved"])==2 and any(x["hotspot"] for x in j["saved"]),j)
s,j,_=call("POST","/api/wifi/connect",{"ssid":"-x","password":"12345678"}); chk("SSID que empieza por - rechazado",s==400)
s,j,_=call("POST","/api/wifi/connect",{"ssid":"Red","password":"corta"}); chk("clave corta rechazada",s==400)
s,j,_=call("POST","/api/wifi/connect",{"ssid":"A"*40,"password":"12345678"}); chk("SSID largo rechazado",s==400)
s,j,_=call("POST","/api/wifi/connect",{"ssid":"MALA","password":"12345678"}); chk("connect arranca tarea",s==202)
for _ in range(30):
    s,j,_=call("GET","/api/job")
    if not j["running"]: break
    time.sleep(1)
print("   tarea:",j["name"],"ok=",j["ok"]); print("   "+"\n   ".join(j["log"]))
chk("fallo -> rescate",j["ok"] is False and any("Recuperación" in l for l in j["log"]))
time.sleep(4)
s,j,_=call("POST","/api/wifi/connect",{"ssid":"Buena","password":"12345678"}); chk("connect bueno arranca",s==202)
for _ in range(60):
    s,j,_=call("GET","/api/job")
    if not j["running"]: break
    time.sleep(1)
print("   "+"\n   ".join(j["log"])); chk("connect bueno OK",j["ok"] is True)
s,j,_=call("POST","/api/wifi/forget",{"name":"hotspot"}); chk("no borra hotspot",s==400)
s,j,_=call("POST","/api/wifi/forget",{"name":"br0"}); chk("no borra no-wifi",s==404)
s,j,_=call("POST","/api/modem/apn",{"apn":"internet; rm -rf /","user":""}); chk("APN con inyección rechazado",s==400)
s,j,_=call("POST","/api/modem/apn",{"apn":"movistar.es","user":"movistar","password":"movistar"}); chk("APN ok",s==200)
s,j,_=call("POST","/api/modem/pin",{"pin":"12"}); chk("PIN corto rechazado",s==400)
s,j,_=call("POST","/api/modem/pin",{"pin":"1234"}); chk("PIN ok",s==200,j)
s,j,_=call("POST","/api/tailscale",{"action":"noroutes"}); chk("tailscale noroutes",s==200)
s,j,_=call("POST","/api/tailscale",{"action":"rm -rf"}); chk("tailscale acción rara = 400",s==400)
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1; reboot","baud":115200,"port":4403,"bind":"tailscale"}); chk("device con inyección rechazado",s==400)
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1","baud":1234,"port":4403,"bind":"tailscale"}); chk("baud raro rechazado",s==400)
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1","baud":115200,"port":22,"bind":"tailscale"}); chk("puerto <1024 rechazado",s==400)
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1","baud":115200,"port":4403,"bind":"1.2.3.4;ls"}); chk("bind raro rechazado",s==400)
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1","baud":115200,"port":4403,"bind":"0.0.0.0"}); chk("0.0.0.0 avisa",s==200 and j["warning"])
s,j,_=call("POST","/api/bridge/config",{"device":"/dev/ttyMSM1","baud":115200,"port":4403,"bind":"tailscale"}); chk("config buena",s==200 and not j["warning"])
s,j,_=call("GET","/api/bridge"); chk("bridge refleja config",j["config"]["device"]=="/dev/ttyMSM1" and not j["device_exists"])
s,j,_=call("POST","/api/bridge/action",{"action":"start"}); chk("start",s==200)
s,j,_=call("POST","/api/bridge/action",{"action":"exec"}); chk("acción rara = 400",s==400)
s,j,_=call("POST","/api/bridge/probe",{}); chk("probe sin dispositivo = 400",s==400,j)
for u in ["panel","bridge","tailscale","red","modem"]:
    s,j,_=call("GET","/api/logs?unit="+u); assert s==200 and "registro" in j["text"],(u,j)
chk("logs de las 5 unidades",True)
s,j,_=call("GET","/api/logs?unit=../../etc/passwd"); chk("logs unidad no permitida",s==400)
s,j,_=call("POST","/api/panel/password",{"old":"mala","new":"otra-clave-123"}); chk("cambio de clave exige la actual",s==403)
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1","new":"abcd"}); chk("clave nueva corta rechazada",s==400)
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1","new":"otra-clave-123"}); chk("cambio de clave",s==200)
s,j,sc=call("POST","/api/login",{"username":"admin","password":"clave-de-prueba-1"}); chk("la clave vieja ya no vale",s==401)
s,j,_=call("POST","/api/logout",{}); chk("logout",s==200)
s,j,_=call("GET","/api/status"); chk("tras logout = 401",s==401)
# límite de intentos
codes=[call("POST","/api/login",{"username":"admin","password":"z%d"%i},ck=False)[0] for i in range(7)]
print("   intentos:",codes); chk("bloqueo tras 5 fallos",429 in codes)
s,j,_=call("POST","/api/login",{"username":"admin","password":"otra-clave-123"}); chk("bloqueado incluso con clave buena",s==429)
print("TODO OK")

