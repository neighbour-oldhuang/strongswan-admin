import subprocess, shutil, re

def run(cmd: str, input_text: str = None, timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(
        cmd, shell=True, capture_output=True, text=True,
        input=input_text, timeout=timeout
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def run_bg(cmd: str) -> tuple[int, str, str]:
    """fire-and-forget，不等待结果"""
    subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0, "命令已发送，请稍后查看 SA 状态", ""

def is_installed() -> bool:
    return shutil.which("swanctl") is not None or shutil.which("ipsec") is not None

def status() -> dict:
    code, out, err = run("systemctl is-active strongswan 2>/dev/null || systemctl is-active strongswan-starter 2>/dev/null || echo unknown")
    active = out.strip() == "active"
    _, sa_out, _ = run("swanctl --list-sas 2>/dev/null || ipsec statusall 2>/dev/null || echo '(no output)'")
    return {"active": active, "raw": sa_out or err}

def start():  return run("systemctl start strongswan 2>/dev/null || systemctl start strongswan-starter 2>/dev/null || ipsec start")
def stop():   return run("systemctl stop strongswan 2>/dev/null || systemctl stop strongswan-starter 2>/dev/null || ipsec stop")
def restart():return run("systemctl restart strongswan 2>/dev/null || systemctl restart strongswan-starter 2>/dev/null || ipsec restart")
def reload(): return run("swanctl --load-all 2>/dev/null") if shutil.which("swanctl") else run("ipsec reload")

def get_logs(lines=80) -> str:
    _, out, _ = run(f"journalctl -u strongswan -u strongswan-starter -n {lines} --no-pager 2>/dev/null || tail -n {lines} /var/log/syslog 2>/dev/null | grep -i charon || echo '(no logs)'")
    return out

def generate_cert(cn: str, days: int = 3650) -> tuple:
    """生成自签名 CA、本端证书和私钥，写入 swanctl 标准目录"""
    import os
    if not re.fullmatch(r'[A-Za-z0-9._-]+', cn):
        return 1, "", "CN 只允许字母、数字、点、连字符和下划线"
    os.makedirs("/etc/swanctl/x509ca", exist_ok=True)
    os.makedirs("/etc/swanctl/x509", exist_ok=True)
    os.makedirs("/etc/swanctl/private", exist_ok=True)

    ca_key  = f"/etc/swanctl/private/{cn}-ca.key.pem"
    ca_cert = f"/etc/swanctl/x509ca/{cn}-ca.pem"
    sv_key  = f"/etc/swanctl/private/{cn}.key.pem"
    sv_cert = f"/etc/swanctl/x509/{cn}.pem"

    cmds = [
        # CA 私钥 + 自签名证书
        f'pki --gen --type rsa --size 4096 --outform pem > {ca_key}',
        f'pki --self --ca --lifetime {days} --in {ca_key} --type rsa --dn "CN={cn} CA" --outform pem > {ca_cert}',
        # 本端私钥 + 由 CA 签发的证书
        f'pki --gen --type rsa --size 2048 --outform pem > {sv_key}',
        f'pki --issue --lifetime {days} --cacert {ca_cert} --cakey {ca_key} --type rsa --in {sv_key} --dn "CN={cn}" --san {cn} --outform pem > {sv_cert}',
    ]
    for cmd in cmds:
        code, out, err = run(cmd)
        if code != 0:
            return code, out, err
    return 0, f"CA: {cn}-ca.pem  证书: {cn}.pem  私钥: {cn}.key.pem", ""

# ── kernel / routing helpers ──────────────────────────────────────────────────

SYSCTL_FILE = "/etc/sysctl.d/99-ipsec.conf"

RECOMMENDED_SYSCTLS = {
    "net.ipv4.ip_forward":                    "1",
    "net.ipv4.conf.all.accept_redirects":     "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects":       "0",
    "net.ipv4.conf.default.send_redirects":   "0",
    "net.ipv4.conf.all.rp_filter":            "0",
    "net.ipv4.conf.default.rp_filter":        "0",
}

def get_sysctls() -> dict:
    """返回每个推荐参数的当前值及是否符合推荐值"""
    result = {}
    for key, recommended in RECOMMENDED_SYSCTLS.items():
        _, val, _ = run(f"sysctl -n {key} 2>/dev/null")
        result[key] = {"current": val.strip(), "recommended": recommended, "ok": val.strip() == recommended}
    return result

def apply_sysctls() -> tuple:
    """写入持久化文件并立即生效"""
    import os
    lines = [f"{k} = {v}" for k, v in RECOMMENDED_SYSCTLS.items()]
    with open(SYSCTL_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    return run("sysctl -p " + SYSCTL_FILE)

def get_routes() -> str:
    _, out, _ = run("ip route show")
    return out

def _route_cmd(action: str, dst: str, via: str, dev: str) -> tuple:
    cmd = ["ip", "route", action, dst]
    if via: cmd += ["via", via]
    if dev: cmd += ["dev", dev]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def add_route(dst: str, via: str, dev: str) -> tuple:
    return _route_cmd("add", dst, via, dev)

def del_route(dst: str, via: str, dev: str) -> tuple:
    return _route_cmd("del", dst, via, dev)

def install():
    """通过 apt-get 安装 strongswan，以生成器方式 yield 进度行"""
    import subprocess, sys
    pkgs = "strongswan strongswan-pki strongswan-swanctl charon-systemd libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins"
    cmd = ["apt-get", "install", "-y", pkgs]
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    # 先 update
    yield ">>> apt-get update ...\n"
    proc = subprocess.Popen(["apt-get", "update", "-y"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    for line in proc.stdout:
        yield line
    proc.wait()
    yield f">>> apt-get install {pkgs} ...\n"
    proc = subprocess.Popen(["apt-get", "install", "-y"] + pkgs.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    for line in proc.stdout:
        yield line
    rc = proc.wait()
    if rc == 0:
        yield ">>> ✅ 安装完成！\n"
    else:
        yield f">>> ❌ 安装失败，退出码 {rc}\n"

def write_swanctl(connections: dict):
    """Generate /etc/swanctl/conf.d/admin.conf from stored connections."""
    import os
    lines = []
    conn_block = []
    pool_block = []
    secret_block = []

    for idx, (name, c) in enumerate(connections.items(), start=1):
        if_id = idx
        auth_local = c.get("auth_local", "pubkey")
        auth_remote = c.get("auth_remote", "pubkey")

        conn_block.append(f"    {name} {{")
        conn_block.append(f"        version = {c.get('ike_version', 2)}")
        if c.get("local_addr"):  conn_block.append(f"        local_addrs = {c['local_addr']}")
        if c.get("remote_addr"): conn_block.append(f"        remote_addrs = {c['remote_addr']}")
        if c.get("proposals"):   conn_block.append(f"        proposals = {c['proposals']}")
        if c.get("dpd_delay"):   conn_block.append(f"        dpd_delay = {c['dpd_delay']}")
        if c.get("dpd_timeout"): conn_block.append(f"        dpd_timeout = {c['dpd_timeout']}")
        if c.get("keyingtries"):
            kt = c["keyingtries"].replace("%forever", "0")
            conn_block.append(f"        keyingtries = {kt}")

        # local auth
        conn_block.append(f"        local {{")
        conn_block.append(f"            auth = {auth_local}")
        if c.get("local_id"):    conn_block.append(f"            id = {c['local_id']}")
        if auth_local == "pubkey" and c.get("local_cert"):
            conn_block.append(f"            certs = {c['local_cert']}")
        conn_block.append(f"        }}")

        # remote auth
        conn_block.append(f"        remote {{")
        conn_block.append(f"            auth = {auth_remote}")
        if c.get("remote_id"):   conn_block.append(f"            id = {c['remote_id']}")
        if auth_remote == "pubkey" and c.get("remote_cert"):
            conn_block.append(f"            certs = {c['remote_cert']}")
        conn_block.append(f"        }}")

        # children (SA)
        conn_block.append(f"        children {{")
        conn_block.append(f"            {name}_child {{")
        if c.get("local_ts"):    conn_block.append(f"                local_ts = {c['local_ts']}")
        if c.get("remote_ts"):   conn_block.append(f"                remote_ts = {c['remote_ts']}")
        if c.get("esp_proposals"):conn_block.append(f"                esp_proposals = {c['esp_proposals']}")
        mode = c.get("mode", "tunnel")
        conn_block.append(f"                mode = {mode}")
        if c.get("use_xfrm"):
            conn_block.append(f"                if_id_in = {if_id}")
            conn_block.append(f"                if_id_out = {if_id}")
        if c.get("start_action"):conn_block.append(f"                start_action = {c['start_action']}")
        if c.get("dpd_action"):  conn_block.append(f"                dpd_action = {c['dpd_action']}")
        conn_block.append(f"            }}")
        conn_block.append(f"        }}")
        conn_block.append(f"    }}")

        # PSK secret
        if auth_local == "psk" and c.get("psk"):
            secret_block.append(f"    ike-{name} {{")
            secret_block.append(f"        secret = {c['psk']}")
            if c.get("local_id"):  secret_block.append(f"        id-local = {c['local_id']}")
            if c.get("remote_id"): secret_block.append(f"        id-remote = {c['remote_id']}")
            secret_block.append(f"    }}")

    lines.append("connections {")
    lines.extend(conn_block)
    lines.append("}")
    if secret_block:
        lines.append("\nsecrets {")
        lines.extend(secret_block)
        lines.append("}")

    conf_dir = "/etc/swanctl/conf.d"
    os.makedirs(conf_dir, exist_ok=True)
    with open(f"{conf_dir}/admin.conf", "w") as f:
        f.write("\n".join(lines) + "\n")

    # 自动创建/确保 xfrm 接口存在
    for idx, (name, c) in enumerate(connections.items(), start=1):
        if c.get("use_xfrm"):
            iface = f"xfrm{idx}"
            run(f"ip link show {iface} 2>/dev/null || ip link add {iface} type xfrm if_id {idx}")
            run(f"ip link set {iface} up")
