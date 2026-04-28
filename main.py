from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import store, ctl, nat, shutil, os, re, auth

app = FastAPI(title="StrongSwan Admin")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
auth.setup(app)

# ── helpers ──────────────────────────────────────────────────────────────────

def redirect(path, msg="", ok=True):
    sep = "?" if "?" not in path else "&"
    tag = "ok" if ok else "err"
    return RedirectResponse(f"{path}{sep}{tag}={msg}", status_code=303)

# ── pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    data = store.load()
    st = ctl.status()
    installed = ctl.is_installed()
    return templates.TemplateResponse("index.html", {
        "request": request, "data": data,
        "status": st, "installed": installed,
        "ok": request.query_params.get("ok"),
        "err": request.query_params.get("err"),
        "needs_reload": store.needs_reload(),
    })

# ── system config (sysctl + routes) ──────────────────────────────────────────

@app.get("/system", response_class=HTMLResponse)
async def system_page(request: Request):
    return templates.TemplateResponse("system.html", {
        "request": request,
        "ok":  request.query_params.get("ok"),
        "err": request.query_params.get("err"),
    })

@app.get("/api/sysctls")
async def api_sysctls():
    return JSONResponse(ctl.get_sysctls())

@app.post("/system/sysctl/apply")
async def sysctl_apply():
    code, out, err = ctl.apply_sysctls()
    return redirect("/", out or err or "内核参数已应用并持久化", code == 0)

@app.get("/api/charon")
async def api_charon():
    return JSONResponse(ctl.get_charon_params())

@app.post("/api/charon")
async def api_charon_save(request: Request):
    data = await request.json()
    for key, val in data.items():
        if key in ctl.CHARON_PARAMS and val:
            code, out, err = ctl.set_charon_param(key, val)
            if code != 0:
                return JSONResponse({"ok": False, "msg": err})
    return JSONResponse({"ok": True})

@app.get("/api/routes")
async def api_routes():
    return JSONResponse({"routes": ctl.get_routes()})

@app.post("/system/route/add")
async def route_add(request: Request, dst: str = Form(...), via: str = Form(""), dev: str = Form("")):
    code, out, err = ctl.add_route(dst.strip(), via.strip(), dev.strip())
    if request.headers.get("accept") == "application/json":
        return JSONResponse({"ok": code == 0, "msg": out or err})
    return redirect("/system", out or err or f"路由 {dst} 已添加", code == 0)

@app.post("/system/route/del")
async def route_del(request: Request, dst: str = Form(...), via: str = Form(""), dev: str = Form("")):
    code, out, err = ctl.del_route(dst.strip(), via.strip(), dev.strip())
    if request.headers.get("accept") == "application/json":
        return JSONResponse({"ok": code == 0, "msg": out or err})
    return redirect("/system", out or err or f"路由 {dst} 已删除", code == 0)

# ── OIDC settings ─────────────────────────────────────────────────────────────

@app.get("/api/oidc")
async def api_oidc_get():
    return JSONResponse(auth.get_cfg())

@app.post("/api/oidc")
async def api_oidc_save(request: Request):
    body = await request.json()
    auth.save_cfg({
        "enabled":        body.get("enabled", False),
        "issuer":         str(body.get("issuer", "")).strip(),
        "client_id":      str(body.get("client_id", "")).strip(),
        "client_secret":  str(body.get("client_secret", "")).strip(),
        "redirect_uri":   str(body.get("redirect_uri", "")).strip(),
        "required_group": str(body.get("required_group", "opsadmin")).strip(),
    })
    return JSONResponse({"ok": True, "msg": "OIDC 配置已保存"})

# ── NAT management ────────────────────────────────────────────────────────────

@app.get("/nat", response_class=HTMLResponse)
async def nat_page(request: Request):
    data = store.load()
    nat_cfg = data.get("nat", {"subnets": [], "out_iface": "", "proxy_ipsec": False})
    return templates.TemplateResponse("nat.html", {
        "request": request, "nat_cfg": nat_cfg,
        "ok": request.query_params.get("ok"),
        "err": request.query_params.get("err"),
    })

@app.get("/api/nat/env")
async def api_nat_env():
    return JSONResponse(nat.check_env())

@app.get("/api/nat/rules")
async def api_nat_rules():
    return JSONResponse({"rules": nat.get_current_rules()})

@app.get("/api/nat/optimize-status")
async def api_nat_opt_status():
    return JSONResponse(nat.get_optimize_status())

@app.post("/nat/apply")
async def nat_apply(request: Request,
                    subnets: str = Form(""), out_iface: str = Form(""),
                    proxy_ipsec: str = Form("")):
    subnet_list = [s.strip() for s in subnets.splitlines() if s.strip()]
    iface = out_iface.strip() or nat.check_env().get("default_iface", "")
    do_proxy = proxy_ipsec == "1"
    data = store.load()
    nat_cfg = data.get("nat", {})
    nat_cfg.update({"subnets": subnet_list, "out_iface": iface, "proxy_ipsec": do_proxy})
    data["nat"] = nat_cfg
    store.save(data)
    dnat_rules = nat_cfg.get("dnat_rules", [])
    code, out, err = nat.apply_nat(subnet_list, iface, do_proxy, dnat_rules)
    return redirect("/nat", out or err, code == 0)

@app.post("/nat/stop")
async def nat_stop():
    code, out, err = nat.stop_nat()
    return redirect("/nat", out or err, code == 0)

@app.post("/nat/optimize")
async def nat_optimize():
    code, out, err = nat.optimize_snat()
    return redirect("/nat", out or err, code == 0)

@app.get("/nat/install-nft")
async def nat_install_nft():
    def stream():
        yield from (f"data: {line}\n\n" for line in ctl.pkg_install_stream("nftables"))
        yield "data: __DONE__\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")

# ── DNAT management ───────────────────────────────────────────────────────────

@app.get("/api/nat/dnat")
async def api_dnat_list():
    data = store.load()
    return JSONResponse({"rules": data.get("nat", {}).get("dnat_rules", [])})

@app.post("/api/nat/dnat")
async def api_dnat_add(request: Request):
    body = await request.json()
    proto = body.get("proto", "tcp")
    dport = str(body.get("dport", "")).strip()
    to_addr = str(body.get("to_addr", "")).strip()
    to_port = str(body.get("to_port", "")).strip()
    comment = str(body.get("comment", "")).strip()
    if not dport or not to_addr:
        return JSONResponse({"ok": False, "msg": "外部端口和目标地址不能为空"})
    conflict = nat.check_port_conflict(proto, dport)
    if conflict:
        return JSONResponse({"ok": False, "msg": conflict})
    rule = {"proto": proto, "dport": dport, "to_addr": to_addr, "to_port": to_port, "comment": comment}
    data = store.load()
    nat_cfg = data.setdefault("nat", {"subnets": [], "out_iface": "", "proxy_ipsec": False})
    rules = nat_cfg.setdefault("dnat_rules", [])
    rules.append(rule)
    store.save(data)
    # 重新应用全部 NAT 规则
    code, out, err = nat.apply_nat(
        nat_cfg.get("subnets", []),
        nat_cfg.get("out_iface", "") or nat.check_env().get("default_iface", ""),
        nat_cfg.get("proxy_ipsec", False),
        rules,
    )
    return JSONResponse({"ok": code == 0, "msg": out or err})

@app.post("/api/nat/dnat/delete")
async def api_dnat_delete(request: Request):
    body = await request.json()
    idx = body.get("index", -1)
    data = store.load()
    rules = data.get("nat", {}).get("dnat_rules", [])
    if not (0 <= idx < len(rules)):
        return JSONResponse({"ok": False, "msg": "索引无效"})
    rules.pop(idx)
    data["nat"]["dnat_rules"] = rules
    store.save(data)
    nat_cfg = data["nat"]
    code, out, err = nat.apply_nat(
        nat_cfg.get("subnets", []),
        nat_cfg.get("out_iface", "") or nat.check_env().get("default_iface", ""),
        nat_cfg.get("proxy_ipsec", False),
        rules,
    )
    return JSONResponse({"ok": code == 0, "msg": out or err or "DNAT 规则已删除"})

# ── instance control ──────────────────────────────────────────────────────────

@app.get("/instance/install")
async def inst_install():
    def event_stream():
        for line in ctl.install():
            yield f"data: {line}\n\n"
        yield "data: __DONE__\n\n"
    return StreamingResponse(event_stream(), media_type="text/event-stream")

@app.post("/instance/start")
async def inst_start():
    code, out, err = ctl.start()
    msg = out or err or "done"
    return redirect("/", msg, code == 0)

@app.post("/instance/stop")
async def inst_stop():
    code, out, err = ctl.stop()
    return redirect("/", out or err or "done", code == 0)

@app.post("/instance/restart")
async def inst_restart():
    code, out, err = ctl.restart()
    return redirect("/", out or err or "done", code == 0)

@app.post("/instance/reload")
async def inst_reload():
    code, out, err = ctl.reload()
    if code == 0:
        store.clear_reload_flag()
    return redirect("/", out or err or "done", code == 0)

# ── connections ───────────────────────────────────────────────────────────────

_COMMON_FIELDS = [
    ("name",          "连接名称",       "text",   "my-vpn",          "唯一标识，仅字母数字和连字符"),
    ("ike_version",   "IKE 版本",       "select", "2",               "IKEv2 更安全推荐；IKEv1 兼容旧设备"),
    ("local_addr",    "本端地址",        "text",   "%any",            "本机 IP 或 %any（自动）"),
    ("remote_addr",   "对端地址",        "text",   "1.2.3.4",         "对端网关 IP 或域名"),
    ("auth_local",    "本端认证方式",    "select", "psk",             "psk=预共享密钥；pubkey=证书"),
    ("auth_remote",   "对端认证方式",    "select", "psk",             "同上"),
    ("psk",           "预共享密钥 PSK", "password","",               "auth=psk 时填写，双端必须一致"),
    ("local_cert",    "本端证书文件名",  "text",   "",                "pubkey 认证时，x509/ 下的文件名"),
    ("remote_cert",   "对端证书文件名",  "text",   "",                "pubkey 认证时，x509ca/ 下的 CA 文件名"),
    ("proposals",     "IKE 加密提案",   "select", "aes256-sha256-modp2048", "格式：加密-完整性-DH组，如 modp2048=DH14、modp1024=DH2、ecp256=DH19、ecp384=DH20，需与对端一致"),
    ("esp_proposals", "ESP 加密提案",   "select", "aes256-sha256",          "格式：加密-完整性，对应对端 IPSec/ESP 算法配置，需与对端一致"),
    ("start_action",  "启动动作",        "select", "none",            "none=手动；start=自动发起；trap=按需触发"),
]

_ADVANCED_FIELDS = [
    ("local_id",      "本端 ID",        "text",   "",                "IKE 身份标识，留空使用地址"),
    ("remote_id",     "对端 ID",        "text",   "",                "对端身份标识，留空使用地址"),
    ("dpd_action",    "DPD 动作",       "select", "restart",         "Dead Peer Detection检测到对端失联后的动作：restart=自动重连（推荐）；clear=清除SA不重连；none=忽略，不做任何处理"),
    ("dpd_delay",     "DPD 检测间隔(s)","select", "30",              "Dead Peer Detection 心跳间隔秒数，越小检测越快但开销越大，30s适合大多数场景"),
    ("dpd_timeout",   "DPD 超时(s)",    "select", "150",             "连续无响应超过此时间则判定对端失联并触发DPD动作，建议为dpd_delay的3~5倍"),
    ("keyingtries",   "重协商次数",      "select", "0",               "0=永久重试；3/5=固定次数；swanctl不支持%forever"),
    ("ike_rekey",     "IKE SA 生命周期(s)", "select", "",             "IKE SA 到期后重新协商，留空使用默认值(14400s)，建议比对端短几分钟避免同时rekey"),
    ("child_rekey",   "IPSec SA 生命周期(s)","select", "",            "ESP SA 到期后重新协商，留空使用默认值(3600s)，建议比对端短几分钟"),
    ("unique",        "重复SA处理",     "select", "",                "对端用新IP重连时如何处理旧SA：replace=立即替换旧SA（推荐拨号/动态IP场景，避免旧SA删除超时导致数分钟断网）；keep=保留旧SA不处理；no=允许同一对端建立多个SA；留空使用默认值(no)"),
    ("close_action",  "关闭动作",       "select", "",                "对端主动关闭CHILD_SA后本端的动作：start=立即重新发起连接（推荐需要保持隧道常通的场景）；trap=等有流量时再按需触发；none=不处理；留空使用默认值(none)"),
    ("over_time",     "SA 超时宽限期(s)","select", "",               "IKE rekey发起后，若对端未响应（如正在换IP），额外等待多久才彻底删除SA。例如rekey_time=86400且over_time=3600，则最长等25小时。留空默认为rekey_time的10%，一般无需修改"),
]

# policy-based 独有字段
POLICY_FIELDS = _COMMON_FIELDS + [
    ("local_ts",  "本端子网", "datalist", "0.0.0.0/0", "本端允许通过 VPN 的流量范围，多个网段用逗号分隔，如 192.168.8.0/24,192.168.9.0/24"),
    ("remote_ts", "对端子网", "datalist", "0.0.0.0/0", "对端允许通过 VPN 的流量范围，多个网段用逗号分隔"),
    ("mode",      "隧道模式", "select", "tunnel",   "tunnel=隧道模式（常用）；transport=传输模式"),
]

# route-based 独有字段（去掉 local_ts/remote_ts/mode，后端硬编码）
ROUTE_FIELDS = _COMMON_FIELDS[:]

CONN_FIELDS = POLICY_FIELDS  # 兼容编辑时的默认值

ADVANCED_KEYS = {f[0] for f in _ADVANCED_FIELDS}

SELECT_OPTIONS = {
    "ike_version":  ["2", "1"],
    "auth_local":   ["psk", "pubkey", "eap-mschapv2", "eap-radius"],
    "auth_remote":  ["psk", "pubkey", "eap-mschapv2", "eap-radius"],
    "mode":         ["tunnel", "transport"],
    "start_action": ["none", "start", "trap"],
    "dpd_action":   ["restart", "clear", "none"],
    "proposals":    [
        "aes256gcm16-prfsha384-ecp384",
        "aes256-sha256-modp2048",
        "aes128-sha256-modp2048",
        "aes128-sha1-modp1024",
        "aes256-sha256-modp1024",
    ],
    "esp_proposals": [
        "aes256gcm16-ecp384",
        "aes256-sha256",
        "aes128-sha256",
        "aes128-sha1",
        "aes256-sha1",
    ],
    "dpd_delay":    ["10", "30", "60", "120"],
    "dpd_timeout":  ["60", "150", "300"],
    "keyingtries":  ["0", "3", "5", "10"],
    "ike_rekey":    ["", "13800", "14400", "28800", "82800", "86400"],
    "child_rekey":  ["", "3300", "3600", "7200", "28800"],
    "unique":       ["", "replace", "keep", "no"],
    "close_action": ["", "start", "none", "trap"],
    "over_time":    ["", "1800", "3600", "7200"],
}

def _fields_for(conn: dict):
    """根据已保存连接判断用哪套字段"""
    return ROUTE_FIELDS if conn.get("use_xfrm") else POLICY_FIELDS

def _cert_lists():
    def ls(p): return sorted(f.name for f in Path(p).glob("*") if f.is_file()) if Path(p).exists() else []
    return {
        "local_certs": ls(f"{ctl.SWANCTL_DIR}/x509"),
        "ca_certs":    ls(f"{ctl.SWANCTL_DIR}/x509ca"),
    }

@app.get("/connections/new", response_class=HTMLResponse)
async def conn_new(request: Request):
    return templates.TemplateResponse("conn_new.html", {"request": request})

@app.get("/connections/new/policy", response_class=HTMLResponse)
async def conn_new_policy(request: Request):
    return templates.TemplateResponse("conn_form.html", {
        "request": request, "fields": POLICY_FIELDS, "adv_fields": _ADVANCED_FIELDS,
        "select_options": SELECT_OPTIONS, **_cert_lists(),
        "conn": {}, "edit": False, "vpn_type": "policy",
        "err": request.query_params.get("err"),
    })

@app.get("/connections/new/route", response_class=HTMLResponse)
async def conn_new_route(request: Request):
    return templates.TemplateResponse("conn_form.html", {
        "request": request, "fields": ROUTE_FIELDS, "adv_fields": _ADVANCED_FIELDS,
        "select_options": SELECT_OPTIONS, **_cert_lists(),
        "conn": {}, "edit": False, "vpn_type": "route",
        "err": request.query_params.get("err"),
    })

@app.post("/connections/new")
async def conn_create(request: Request):
    form = await request.form()
    data = store.load()
    name = form.get("name", "").strip()
    vpn_type = form.get("vpn_type", "policy")
    fields = ROUTE_FIELDS if vpn_type == "route" else POLICY_FIELDS
    if not name:
        return redirect(f"/connections/new/{vpn_type}", "连接名称不能为空", False)
    if name in data["connections"]:
        return redirect(f"/connections/new/{vpn_type}", f"连接 {name} 已存在", False)
    data["connections"][name] = {k: form.get(k, "").strip() for k, *_ in fields + _ADVANCED_FIELDS if k != "name"}
    data["connections"][name]["use_xfrm"] = (vpn_type == "route")
    store.save(data)
    try:
        ctl.write_swanctl(data["connections"])
    except Exception as e:
        return redirect("/", f"配置已保存但写入失败: {e}", False)
    return redirect("/", f"连接 {name} 已创建")

@app.get("/connections/{name}/edit", response_class=HTMLResponse)
async def conn_edit(request: Request, name: str):
    data = store.load()
    conn = data["connections"].get(name)
    if not conn:
        return redirect("/", "连接不存在", False)
    conn["name"] = name
    fields = _fields_for(conn)
    vpn_type = "route" if conn.get("use_xfrm") else "policy"
    return templates.TemplateResponse("conn_form.html", {
        "request": request, "fields": fields, "adv_fields": _ADVANCED_FIELDS,
        "select_options": SELECT_OPTIONS, **_cert_lists(),
        "conn": conn, "edit": True, "vpn_type": vpn_type,
        "err": request.query_params.get("err"),
    })

@app.post("/connections/{name}/edit")
async def conn_update(request: Request, name: str):
    form = await request.form()
    data = store.load()
    if name not in data["connections"]:
        return redirect("/", "连接不存在", False)
    vpn_type = form.get("vpn_type", "policy")
    fields = ROUTE_FIELDS if vpn_type == "route" else POLICY_FIELDS
    data["connections"][name] = {k: form.get(k, "").strip() for k, *_ in fields + _ADVANCED_FIELDS if k != "name"}
    data["connections"][name]["use_xfrm"] = (vpn_type == "route")
    store.save(data)
    try:
        ctl.write_swanctl(data["connections"])
    except Exception as e:
        return redirect("/", f"配置已保存但写入失败: {e}", False)
    return redirect("/", f"连接 {name} 已更新")

@app.post("/connections/{name}/delete")
async def conn_delete(name: str):
    data = store.load()
    data["connections"].pop(name, None)
    store.save(data)
    try:
        ctl.write_swanctl(data["connections"])
    except Exception:
        pass
    return redirect("/", f"连接 {name} 已删除")

@app.post("/connections/{name}/up")
async def conn_up(name: str):
    code, out, err = ctl.run_bg(f"ipsec up {name}" if not shutil.which("swanctl") else f"swanctl --initiate --child {name}_child")
    return redirect("/", out or err or "done", code == 0)

@app.post("/connections/{name}/down")
async def conn_down(name: str):
    code, out, err = ctl.run_bg(f"ipsec down {name}" if not shutil.which("swanctl") else f"swanctl --terminate --ike {name}")
    return redirect("/", out or err or "done", code == 0)

# ── certificates ──────────────────────────────────────────────────────────────

@app.get("/certs", response_class=HTMLResponse)
async def certs_page(request: Request):
    def ls(p): return sorted(Path(p).glob("*")) if Path(p).exists() else []
    return templates.TemplateResponse("certs.html", {
        "request": request,
        "ca_certs":    ls(f"{ctl.SWANCTL_DIR}/x509ca"),
        "local_certs": ls(f"{ctl.SWANCTL_DIR}/x509"),
        "private_keys":ls(f"{ctl.SWANCTL_DIR}/private"),
        "ok":  request.query_params.get("ok"),
        "err": request.query_params.get("err"),
    })

@app.post("/certs/upload")
async def cert_upload(cert_type: str = Form(...), file: UploadFile = File(...)):
    dirs = {"ca": f"{ctl.SWANCTL_DIR}/x509ca", "local": f"{ctl.SWANCTL_DIR}/x509", "key": f"{ctl.SWANCTL_DIR}/private"}
    d = dirs.get(cert_type)
    if not d:
        return redirect("/certs", "未知类型", False)
    filename = Path(file.filename).name  # 防路径穿越
    if not re.fullmatch(r'[A-Za-z0-9._-]+', filename):
        return redirect("/certs", "文件名含非法字符", False)
    if Path(filename).suffix.lower() not in {".pem", ".crt", ".cer", ".key"}:
        return redirect("/certs", "仅允许 .pem/.crt/.cer/.key 文件", False)
    content = await file.read()
    if len(content) > 1 * 1024 * 1024:  # 1 MB 上限
        return redirect("/certs", "文件过大（上限 1MB）", False)
    os.makedirs(d, exist_ok=True)
    (Path(d) / filename).write_bytes(content)
    return redirect("/certs", f"{filename} 上传成功")

@app.post("/certs/delete")
async def cert_delete(cert_type: str = Form(...), filename: str = Form(...)):
    dirs = {"ca": f"{ctl.SWANCTL_DIR}/x509ca", "local": f"{ctl.SWANCTL_DIR}/x509", "key": f"{ctl.SWANCTL_DIR}/private"}
    d = dirs.get(cert_type)
    if d:
        p = Path(d) / filename
        if p.exists(): p.unlink()
    return redirect("/certs", f"{filename} 已删除")

# ── config import / export ────────────────────────────────────────────────────

@app.get("/connections/{name}/export")
async def conn_export(name: str):
    import json as _json
    data = store.load()
    conn = data["connections"].get(name)
    if not conn:
        return redirect("/", "连接不存在", False)
    content = _json.dumps({name: conn}, indent=2, ensure_ascii=False)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={name}.json"},
    )

@app.post("/config/import")
async def config_import(file: UploadFile = File(...)):
    import json as _json
    try:
        content = await file.read()
        incoming = _json.loads(content)
        # 支持单连接格式 {name: {...}} 或全量格式 {connections: {...}}
        if "connections" in incoming:
            conns = incoming["connections"]
        else:
            conns = incoming
        if not isinstance(conns, dict):
            return JSONResponse({"ok": False, "msg": "格式错误"})
        data = store.load()
        data["connections"].update(conns)
        store.save(data)
        ctl.write_swanctl(data["connections"])
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "msg": str(e)})

# ── status / logs API ─────────────────────────────────────────────────────────

@app.get("/api/sa-status")
async def api_sa_status():
    """返回 {连接名: {state, detail}} """
    _, out, _ = ctl.run("swanctl --list-sas 2>/dev/null || ipsec statusall 2>/dev/null")
    result = {}
    current = None
    detail_lines = []
    # 状态优先级：ESTABLISHED > REKEYING > CONNECTING > DELETING
    _prio = {"ESTABLISHED": 4, "REKEYING": 3, "CONNECTING": 2, "DELETING": 1}
    for line in out.splitlines():
        m = re.match(r'^(\S+?):\s+#\d+,\s+(\w+)', line)
        if m:
            if current:
                result[current]["detail"] += "\n".join(detail_lines)
            current = m.group(1)
            state = m.group(2)
            if current not in result or _prio.get(state, 0) > _prio.get(result[current]["state"], 0):
                result[current] = {"state": state, "detail": ""}
            detail_lines = [line]
        elif current:
            detail_lines.append(line)
    if current:
        result[current]["detail"] += "\n".join(detail_lines)
    return JSONResponse(result)

@app.get("/api/status")
async def api_status():
    return JSONResponse(ctl.status())

@app.get("/api/traffic")
async def api_traffic():
    return JSONResponse(ctl.get_traffic_stats())

@app.get("/api/logs")
async def api_logs():
    return JSONResponse({"logs": ctl.get_logs()})

@app.get("/api/myip")
async def api_myip():
    import urllib.request
    last_err = ""
    for url in ["https://ifconfig.me", "https://ip.sb"]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip()
            return JSONResponse({"ip": ip, "raw": ip})
        except Exception as e:
            last_err = str(e)
    return JSONResponse({"ip": "", "error": last_err}, status_code=502)

@app.get("/api/gen-psk")
async def api_gen_psk():
    import secrets
    return JSONResponse({"psk": secrets.token_urlsafe(32)})

@app.post("/certs/generate")
async def cert_generate(cn: str = Form(...), days: int = Form(3650)):
    """生成自签名 CA + 本端证书 + 私钥"""
    code, out, err = ctl.generate_cert(cn, days)
    if code != 0:
        return redirect("/certs", err or "生成失败", False)
    return redirect("/certs", f"证书 {cn} 生成成功")
