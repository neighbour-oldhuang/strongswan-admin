"""nftables SNAT 网关管理"""
import subprocess, re
from pathlib import Path

TABLE_NAME = "strongswan_admin_nat"
CHAIN_NAME = "postrouting_snat"
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

def _build_ruleset(subnets: list[str], out_iface: str, proxy_ipsec: bool = False) -> str:
    lines = [
        f"table ip {TABLE_NAME} {{",
        f"    chain {CHAIN_NAME} {{",
        f"        type nat hook postrouting priority srcnat; policy accept;",
    ]
    if not proxy_ipsec:
        # 排除所有 IPSec 流量：
        #   rt ipsec exists  → 匹配被 XFRM policy 标记的包（policy-based）
        #   oifname "xfrm*"  → 匹配走 xfrm 虚拟接口的包（route-based）
        lines.append(f"        rt ipsec exists accept")
        lines.append(f"        oifname \"xfrm*\" accept")
    for subnet in subnets:
        subnet = subnet.strip()
        if not subnet:
            continue
        lines.append(f"        ip saddr {subnet} oifname {out_iface} masquerade")
    lines += ["    }", "}"]
    return "\n".join(lines)


def apply_nat(subnets: list[str], out_iface: str, proxy_ipsec: bool = False) -> tuple[int, str, str]:
    if not subnets or not out_iface:
        return 1, "", "子网列表和出口网卡不能为空"
    # 预加载内核模块，确保 nftables ipsec/xfrm 匹配可用
    run("modprobe nft_xfrm 2>/dev/null")
    run("modprobe xfrm_interface 2>/dev/null")
    ruleset = _build_ruleset(subnets, out_iface, proxy_ipsec)
    run(f"nft delete table ip {TABLE_NAME} 2>/dev/null")
    code, out, err = run("nft -f -", input_text=ruleset)
    if code != 0:
        return code, out, err
    _persist(ruleset)
    return 0, "SNAT 规则已应用", ""


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


def stop_nat() -> tuple[int, str, str]:
    run(f"nft delete table ip {TABLE_NAME} 2>/dev/null")
    p = Path(NFTCONF)
    if p.exists():
        p.unlink()
    return 0, "SNAT 已停止", ""


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
