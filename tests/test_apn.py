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


s,j,sc=call("POST","/api/login",{"username":"admin","password":"clave-de-prueba-1"}); chk("login",s==200,j)
cookie=sc.split(";")[0].split("=",1)[1]

# ---------- APN ----------
s,j,_=call("GET","/api/modem/apns"); chk("apns responde",s==200 and len(j["presets"])>20,j.get("detected"))
chk("detecta Orange por la SIM","orange" in j["detected"]["groups"],j["detected"])
chk("nada recordado al inicio",j["saved"] is None)
s,j,_=call("POST","/api/modem/apn-custom",{"action":"add","label":"Mi operador","apn":"mi.apn","user":"u","password":"p"}); chk("custom add",s==200,j)
s,j,_=call("POST","/api/modem/apn-custom",{"action":"add","label":"x","apn":"mal apn;rm","user":""}); chk("custom con inyección rechazado",s==400)
s,j,_=call("POST","/api/modem/apn-custom",{"action":"add","label":"<b>","apn":"a"}); chk("custom con nombre raro rechazado",s==400)
s,j,_=call("GET","/api/modem/apns"); chk("custom aparece",any(c["label"]=="Mi operador" for c in j["custom"]))
s,j,_=call("POST","/api/modem/apn-custom",{"action":"del","label":"Mi operador"}); chk("custom del",s==200)
s,j,_=call("POST","/api/modem/apn-auto",{"on":False}); chk("auto off",s==200 and j["auto"] is False)
s,j,_=call("POST","/api/modem/apn",{"apn":"orangeworld","user":"orange","password":"orange"}); chk("apn manual ok",s==200)
s,j,_=call("GET","/api/modem/apns"); chk("apn manual se recuerda para la SIM",j["saved"] and j["saved"]["apn"]=="orangeworld",j["saved"])
chk("la clave no se devuelve en 'saved'","password" not in (j["saved"] or {}))
s,j,_=call("POST","/api/modem/connect",{"on":True,"restart":True}); chk("connect con restart",s==202)
for _ in range(40):
    time.sleep(1); s,j,_=call("GET","/api/job")
    if not j["running"]: break
chk("job de datos terminó",not j["running"],j["log"])
s,j,_=call("POST","/api/modem/apn-probe",{}); chk("probe arranca",s==202)
time.sleep(4); s,j,_=call("GET","/api/job")
chk("probe en marcha y registrando intentos",j["running"] and any("Probando" in x for x in j["log"]),j["log"][:3])
s,j,_=call("POST","/api/modem/pin",{"pin":"12"}); chk("PIN corto rechazado",s==400)
s,j,_=call("POST","/api/modem/pin",{"pin":"1234","remember":True}); chk("PIN enviado y recordado",s==200,j)
s,j,_=call("GET","/api/modem/apns"); chk("PIN figura como guardado",j["pin"]["saved"] is True and j["pin"]["auto"] is True)
chk("el PIN no se devuelve","1234" not in json.dumps(j))
s,j,_=call("POST","/api/modem/pin-auto",{"on":False}); chk("pin-auto off",s==200 and j["auto"] is False)
s,j,_=call("POST","/api/modem/pin-forget",{}); chk("pin-forget",s==200)
s,j,_=call("GET","/api/modem/apns"); chk("PIN olvidado",j["pin"]["saved"] is False)
import os,stat
mode=stat.S_IMODE(os.stat(os.environ["OSP_CONFIG"]).st_mode); chk("config con permisos 600",mode==0o600,oct(mode))

# ---------- Usuario y contraseña ----------
s,j,_=call("GET","/api/status"); chk("auth en el estado",j["auth"]["user"]=="admin" and j["auth"]["default_creds"] is False,j["auth"])
c0=cookie
s,j,sc=call("POST","/api/login",{"username":"otro","password":"clave-de-prueba-1"},ck=False); chk("usuario incorrecto = 401",s==401,j)
s,j,sc=call("POST","/api/login",{"username":"admin","password":"mala"},ck=False); chk("clave incorrecta = 401",s==401)
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1"}); chk("sin cambios = 400",s==400)
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1","username":"a b"}); chk("usuario con espacios rechazado",s==400)
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1","username":"ab"}); chk("usuario demasiado corto rechazado",s==400)
s,j,_=call("POST","/api/panel/password",{"old":"mala","username":"operador"}); chk("exige la clave actual",s==403)
s,j,sc2=call("POST","/api/login",{"username":"admin","password":"clave-de-prueba-1"},ck=False); cookie2=sc2.split(";")[0].split("=",1)[1]
s,j,_=call("POST","/api/panel/password",{"old":"clave-de-prueba-1","username":"admin","new":"admin"}); chk("poner admin/admin",s==200,j)
s,j,_=call("GET","/api/status"); chk("se marca como credenciales predeterminadas",j["auth"]["default_creds"] is True)
cookie_keep=cookie; cookie=cookie2
s,j,_=call("GET","/api/status"); chk("la otra sesión se cerró al cambiar",s==401)
cookie=cookie_keep
s,j,sc=call("POST","/api/login",{"username":"admin","password":"admin"},ck=False); chk("login admin/admin",s==200)
s,j,_=call("POST","/api/panel/password",{"old":"admin","username":"operador","new":"clave-nueva-9"}); chk("cambiar usuario y clave",s==200 and j["username"]=="operador",j)
s,j,_=call("GET","/api/status"); chk("ya no son las predeterminadas",j["auth"]["default_creds"] is False and j["auth"]["user"]=="operador")
s,j,_=call("POST","/api/login",{"username":"admin","password":"clave-nueva-9"},ck=False); chk("el usuario antiguo ya no entra",s==401)
s,j,_=call("POST","/api/login",{"username":"operador","password":"clave-nueva-9"},ck=False); chk("entra con el nuevo",s==200)
print("TODO USUARIO OK")
