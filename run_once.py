import os
import asyncio
from checker import collect_nodes, check_nodes
from telegram import Bot

async def main():
    SINGBOX_PATH = os.environ["SINGBOX_PATH"]
    TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
    ADMIN_CHAT_ID = os.environ["ADMIN_CHAT_ID"]
    SUBSCRIPTIONS_FILE = os.environ["SUBSCRIPTIONS_FILE"]

    urls = []
    with open(SUBSCRIPTIONS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)

    nodes = await collect_nodes(urls)
    if not nodes:
        print("No nodes found.")
        return

    from checker import CheckResult
    res: CheckResult = await check_nodes(
        SINGBOX_PATH,
        "127.0.0.1",
        9090,
        "https://cp.cloudflare.com/generate_204",
        6000,
        10,
        nodes
    )

    msg = f"✅ Healthy nodes: {len(res.healthy_links)}\n" + "\n".join(res.healthy_links)
    bot = Bot(token=TELEGRAM_BOT_TOKEN)
    await bot.send_message(chat_id=ADMIN_CHAT_ID, text=msg)

if __name__ == "__main__":
    asyncio.run(main())
