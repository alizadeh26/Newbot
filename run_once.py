from __future__ import annotations
import asyncio
import os
import time
from checker import collect_nodes, check_nodes, render_outputs

import httpx

# تنظیمات از Environment Variable
SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "sing-box")
CLASH_API_HOST = os.environ.get("CLASH_API_HOST", "127.0.0.1")
CLASH_API_PORT = int(os.environ.get("CLASH_API_PORT", 9090))
TEST_URL = os.environ.get("TEST_URL", "https://cp.cloudflare.com/generate_204")
TEST_TIMEOUT_MS = int(os.environ.get("TEST_TIMEOUT_MS", 6000))
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", 10))
SUBS_FILE = os.environ.get("SUBSCRIPTIONS_FILE", "subscriptions.txt")
REFRESH_HOURS = int(os.environ.get("REFRESH_HOURS", 2))
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")


async def send_telegram_message(message: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not ADMIN_CHAT_ID:
        print("Telegram credentials not set")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": ADMIN_CHAT_ID, "text": message, "parse_mode": "HTML"}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.post(url, data=data)
            r.raise_for_status()
        except Exception as e:
            print("Failed to send Telegram message:", e)


async def load_subscription_urls() -> list[str]:
    if not os.path.exists(SUBS_FILE):
        return []
    with open(SUBS_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    return lines


async def main_loop() -> None:
    while True:
        start_time = time.time()
        urls = await load_subscription_urls()
        if not urls:
            print("No subscription URLs found.")
            await asyncio.sleep(REFRESH_HOURS * 3600)
            continue

        print(f"Found {len(urls)} subscriptions, collecting nodes...")
        nodes = await collect_nodes(urls)
        print(f"Collected {len(nodes)} nodes, checking for healthy ones...")

        res = await check_nodes(
            SINGBOX_PATH,
            CLASH_API_HOST,
            CLASH_API_PORT,
            TEST_URL,
            TEST_TIMEOUT_MS,
            MAX_CONCURRENCY,
            nodes,
        )

        txt_bytes, yml_bytes = render_outputs(res)

        # ارسال به تلگرام
        message = (
            f"✅ بررسی اشتراک‌ها به پایان رسید.\n"
            f"🟢 لینک‌های سالم: {len(res.healthy_links)}\n"
            f"🟢 پروکسی‌های Clash سالم: {len(res.healthy_clash_proxies)}"
        )
        await send_telegram_message(message)

        # ذخیره خروجی‌ها در فایل
        with open("healthy.txt", "wb") as f:
            f.write(txt_bytes)
        with open("healthy_clash.yaml", "wb") as f:
            f.write(yml_bytes)

        elapsed = time.time() - start_time
        print(f"Finished in {elapsed:.1f}s. Waiting {REFRESH_HOURS} hours for next check.")
        await asyncio.sleep(REFRESH_HOURS * 3600)


def main():
    asyncio.run(main_loop())


if __name__ == "__main__":
    main()
