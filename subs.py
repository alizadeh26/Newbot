from __future__ import annotations
import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
import yaml

# پروتکل‌های پشتیبانی شده
_PROTOCOL_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://")

@dataclass(frozen=True)
class Node:
    tag: str
    outbound: dict
    export_link: str | None = None
    export_clash_proxy: dict | None = None


# ===========================
# Utility ها
# ===========================
def _safe_tag(s: str) -> str:
    s = s.strip()
    if not s:
        return "proxy"
    s = re.sub(r"\s+", " ", s)
    return s[:64]

def _normalize_ss_method(method: str) -> str:
    m = (method or "").strip().lower()
    if m == "chacha20-poly1305":
        return "chacha20-ietf-poly1305"
    if m == "chacha20":
        return "chacha20-ietf"
    return m

def _is_probably_yaml(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("proxies:") or ("\nproxies:" in t) or ("proxy-groups:" in t)

def _try_b64_decode(text: str) -> str | None:
    s = text.strip()
    if not s:
        return None
    s = re.sub(r"\s+", "", s)
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing
    try:
        b = base64.urlsafe_b64decode(s.encode("utf-8"))
        out = b.decode("utf-8", errors="ignore")
        if any(p in out for p in _PROTOCOL_PREFIXES) or _is_probably_yaml(out):
            return out
        return None
    except Exception:
        return None

# ===========================
# Parsers
# ===========================
def _decode_vmess(link: str) -> dict:
    raw = link[len("vmess://"):].strip()
    missing = (-len(raw)) % 4
    if missing:
        raw += "=" * missing
    return json.loads(base64.b64decode(raw).decode("utf-8"))

def _parse_ss(link: str) -> tuple[str, int, str, str]:
    u = urllib.parse.urlsplit(link)
    name = urllib.parse.unquote(u.fragment) if u.fragment else ""
    netloc = u.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            missing = (-len(userinfo)) % 4
            if missing:
                userinfo += "=" * missing
            method, password = base64.urlsafe_b64decode(userinfo.encode()).decode().split(":", 1)
    else:
        raw = u.path.lstrip("/")
        missing = (-len(raw)) % 4
        if missing:
            raw += "=" * missing
        dec = base64.urlsafe_b64decode(raw.encode()).decode()
        userinfo, hostport = dec.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    host, port_s = hostport.rsplit(":", 1)
    return host, int(port_s), _normalize_ss_method(method), password

# ===========================
# Node از لینک اشتراک
# ===========================
def node_from_share_link(link: str) -> Node | None:
    try:
        if link.startswith("vmess://"):
            v = _decode_vmess(link)
            tag = _safe_tag(v.get("ps") or "vmess")
            outbound = {
                "type": "vmess",
                "tag": tag,
                "server": v.get("add"),
                "server_port": int(v.get("port")),
                "uuid": v.get("id"),
                "security": (v.get("scy") or "auto").lower(),
            }
            if str(v.get("tls") or "").lower() in ("tls", "1", "true"):
                outbound["tls"] = {"enabled": True, "server_name": v.get("sni") or v.get("host") or v.get("add")}
            if (v.get("net") or "tcp").lower() == "ws":
                outbound["transport"] = {"type": "ws", "path": v.get("path") or "/", "headers": {"Host": v.get("host")} if v.get("host") else {}}
            return Node(tag=tag, outbound=outbound, export_link=link)

        if link.startswith("ss://"):
            host, port, method, password = _parse_ss(link)
            if not password:
                return None
            tag = _safe_tag(urllib.parse.unquote(urllib.parse.urlsplit(link).fragment) or "ss")
            outbound = {"type": "shadowsocks", "tag": tag, "server": host, "server_port": port, "method": method, "password": password}
            return Node(tag=tag, outbound=outbound, export_link=link)

        # TODO: اضافه کردن vless و trojan در نسخه بعدی
        return None
    except Exception:
        return None

# ===========================
# Parse اشتراک کامل
# ===========================
def parse_subscription_payload(payload: str) -> list[Node]:
    payload = payload.strip()
    nodes: list[Node] = []

    if _is_probably_yaml(payload):
        data = yaml.safe_load(payload)
        proxies = data.get("proxies") or []
        for p in proxies:
            n = Node(tag=_safe_tag(p.get("name") or "proxy"), outbound=p, export_clash_proxy=p)
            nodes.append(n)
        return nodes

    decoded = _try_b64_decode(payload)
    if decoded:
        return parse_subscription_payload(decoded)

    # خط به خط بررسی می‌کنیم
    for ln in payload.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        n = node_from_share_link(ln)
        if n:
            nodes.append(n)

    return nodes
