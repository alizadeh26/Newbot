from __future__ import annotations
import base64
import json
import urllib.parse
import re
from dataclasses import dataclass
import yaml
import httpx
from checker import collect_nodes, check_nodes
@dataclass(frozen=True)
class Node:
    tag: str
    outbound: dict
    export_link: str | None
    export_clash_proxy: dict | None

_PROTOCOL_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://")

def _safe_tag(s: str) -> str:
    s = s.strip()
    if not s:
        return "proxy"
    s = re.sub(r"\s+", " ", s)
    return s[:64]

async def fetch_text(url: str) -> str:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

def parse_subscription_payload(payload: str) -> tuple[list[str], list[dict]]:
    payload = payload.strip()
    if payload.startswith("proxies:") or "proxy-groups:" in payload:
        data = yaml.safe_load(payload)
        proxies = data.get("proxies") or []
        return [], [p for p in proxies if isinstance(p, dict)]
    # try base64 decode
    try:
        b = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        decoded = b.decode("utf-8", errors="ignore")
        return parse_subscription_payload(decoded)
    except Exception:
        pass
    # fallback: lines with protocol prefix
    lines = [ln.strip() for ln in payload.splitlines() if ln.strip()]
    links = [ln for ln in lines if ln.startswith(_PROTOCOL_PREFIXES)]
    return links, []

def node_from_share_link(link: str) -> Node:
    # فقط نمونه vmess برای سادگی، می‌توان سایر پروتکل‌ها را اضافه کرد
    if link.startswith("vmess://"):
        raw = link[len("vmess://"):]
        raw += "=" * (-len(raw) % 4)
        data = json.loads(base64.b64decode(raw).decode())
        tag = _safe_tag(data.get("ps") or "vmess")
        outbound = {
            "type": "vmess",
            "tag": tag,
            "server": data.get("add"),
            "server_port": int(data.get("port")),
            "uuid": data.get("id"),
            "security": (data.get("scy") or "auto").lower()
        }
        return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)
    raise ValueError("Unsupported link")

def node_from_clash_proxy(proxy: dict) -> Node | None:
    # همینطور که نیاز داری می‌توان گسترش داد
    return None
