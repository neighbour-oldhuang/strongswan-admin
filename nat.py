"""nftables SNAT / DNAT 网关管理"""
import subprocess, re
from pathlib import Path

TABLE_NAME = "strongswan_admin_nat"
CHAIN_SNAT = "postrouting_snat"
CHAIN_DNAT = "prerouting_dnat"
NFTCONF = "/etc/nftables.d/strongswan-admin-snat.conf"


def run(cmd: str, timeout=15, input_text=None) -> tuple[int, str, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       input=input_text, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


# ── 环境检测 ──────────────────────────────────────────────────────────────────

def check_env() -> dict:
    checks = {}
    code, out, _ = run("nft --version 2>/dev/null")
    checks["nftables_installed"] = code == 0
    checks["nftables_version"] = out if code == 0 else ""

    _, val, _ = run("sysctl -n net.ipv4.ip_forward 2>/dev/null")
    checks["ip_forward"] = val.strip() == "1"

    _, route_out, _ = run("ip route show default")
    m = re.search(r"dev (\S+)", route_out)
    checks["default_iface"] = m.group(1) if m else ""

    code, _, _ = run(f"nft list table ip {TABLE_NAME} 2>/dev/null")
    checks["nat_table_active"] = code == 0
    return checks


# ── nftables 规则生成与应用 ────────────────────────────────────────────────────

def get_listening_ports() -> dict[str, set[int]]:
    """返回本机已监听的端口 {"tcp": {22, 80, ...}, "udp": {53, ...}}"""
    result = {"tcp": set(), "udp": set()}
    _, out, _ = run("ss -tlnH 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m:
            result["tcp"].add(int(m.group(1)))
    _, out, _ = run("ss -ulnH 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m:
            result["udp"].add(int(m.group(1)))
    return result


def check_port_conflict(proto: str, dport: str) -> str | None:
    """检查端口是否与本机已监听端口冲突，返回冲突描述或 None"""
    listening = get_listening_ports()
    protos = ["tcp", "udp"] if proto == "tcp+udp" else [proto]
    # 解析端口：支持单端口和范围如 3000-3100
    ports = []
    if "-" in dport:
        parts = dport.split("-", 1)
        try:
            ports = range(int(parts[0]), int(parts[1]) + 1)
        except ValueError:
            return None
    else:
        try:
            ports = [int(dport)]
        except ValueError:
            return None
    conflicts = []
    for p in protos:
        for port in ports:
            if port in listening.get(p, set()):
                conflicts.append(f"{p.upper()}:{port}")
    if conflicts:
        return f"端口 {', '.join(conflicts)} 已被本机占用"
    return None

def _build_ruleset(subnets: list[str], out_iface: str,
                   proxy_ipsec: bool = False,
                   dnat_rules: list[dict] | None = None) -> str:
    lines = [f"table ip {TABLE_NAME} {{"]

    # ── DNAT prerouting chain ──
    if dnat_rules:
        lines.append(f"    chain {CHAIN_DNAT} {{")
        lines.append(f"        type nat hook prerouting priority dstnat; policy accept;")
        for r in dnat_rules:
            proto = r.get("proto", "tcp")
            dport = r.get("dport", "")
            to_addr = r.get("to_addr", "")
            to_port = r.get("to_port", "")
            if not dport or not to_addr:
                continue
            dest = to_addr if not to_port else f"{to_addr}:{to_port}"
            comment = r.get("comment", "")
            protos = ["tcp", "udp"] if proto == "tcp+udp" else [proto]
            for p in protos:
                rule = f"        {p} dport {dport} dnat to {dest}"
                if comment:
                    rule += f" comment \"{comment}\""
                lines.append(rule)
        lines.append(f"    }}")

    # ── SNAT postrouting chain ──
    lines.append(f"    chain {CHAIN_SNAT} {{")
    lines.append(f"        type nat hook postrouting priority srcnat; policy accept;")
    if not proxy_ipsec:
        lines.append(f"        rt ipsec exists accept")
        lines.append(f"        oifname \"xfrm*\" accept")
    for subnet in subnets:
        subnet = subnet.strip()
        if not subnet:
            continue
        lines.append(f"        ip saddr {subnet} oifname {out_iface} masquerade")
    lines.append(f"    }}")

    lines.append("}")
    return "\n".join(lines)


def apply_nat(subnets: list[str], out_iface: str,
              proxy_ipsec: bool = False,
              dnat_rules: list[dict] | None = None) -> tuple[int, str, str]:
    if not subnets and not dnat_rules:
        return 1, "", "至少需要配置 SNAT 子网或 DNAT 规则"
    if subnets and not out_iface:
        return 1, "", "SNAT 需要指定出口网卡"
    run("modprobe nft_xfrm 2>/dev/null")
    run("modprobe xfrm_interface 2>/dev/null")
    ruleset = _build_ruleset(subnets, out_iface or "", proxy_ipsec, dnat_rules)
    run(f"nft delete table ip {TABLE_NAME} 2>/dev/null")
    code, out, err = run("nft -f -", input_text=ruleset)
    if code != 0:
        return code, out, err
    _persist(ruleset)
    return 0, "NAT 规则已应用", ""


def _persist(ruleset: str):
    import os
    os.makedirs("/etc/nftables.d", exist_ok=True)
    Path(NFTCONF).write_text(ruleset + "\n")
    main_conf = Path("/etc/nftables.conf")
    if main_conf.exists():
        content = main_conf.read_text()
        include_line = 'include "/etc/nftables.d/*.conf"'
        if include_line not in content:
            with open(main_conf, "a") as f:
                f.write(f"\n{include_line}\n")
    run("systemctl enable nftables 2>/dev/null")


def stop_nat() -> tuple[int, str, str]:
    run(f"nft delete table ip {TABLE_NAME} 2>/dev/null")
    p = Path(NFTCONF)
    if p.exists():
        p.unlink()
    return 0, "NAT 已停止", ""


def get_current_rules() -> str:
    code, out, _ = run(f"nft list table ip {TABLE_NAME} 2>/dev/null")
    return out if code == 0 else ""


def optimize_snat() -> tuple[int, str, str]:
    run("modprobe nf_conntrack 2>/dev/null")
    params = {
        "net.netfilter.nf_conntrack_max": "262144",
        "net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
        "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "30",
        "net.netfilter.nf_conntrack_udp_timeout": "60",
        "net.netfilter.nf_conntrack_udp_timeout_stream": "180",
        "net.core.netdev_max_backlog": "10000",
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
        "net.ipv4.ip_forward": "1",
    }
    sysctl_file = "/etc/sysctl.d/99-snat-optimize.conf"
    Path(sysctl_file).write_text("\n".join(f"{k} = {v}" for k, v in params.items()) + "\n")
    code, out, err = run(f"sysctl -p {sysctl_file}")
    return code, out or "SNAT 性能参数已优化并持久化", err


def get_optimize_status() -> dict:
    run("modprobe nf_conntrack 2>/dev/null")
    params = {
        "net.netfilter.nf_conntrack_max": "262144",
        "net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
        "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "30",
        "net.netfilter.nf_conntrack_udp_timeout": "60",
        "net.netfilter.nf_conntrack_udp_timeout_stream": "180",
        "net.core.netdev_max_backlog": "10000",
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
        "net.ipv4.ip_forward": "1",
    }
    result = {}
    for key, recommended in params.items():
        _, val, _ = run(f"sysctl -n {key} 2>/dev/null")
        result[key] = {"current": val.strip(), "recommended": recommended, "ok": val.strip() == recommended}
    return result
