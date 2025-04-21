#!/usr/bin/env python3
"""
watches sentinel_logs/ & logs/, broadcasts new lines over WebSocket ws://localhost:8765
"""
import asyncio, pathlib, re, time
import websockets
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_DIRS = ["sentinel_logs", "logs"]
EMOJI_MAP = {r"(TEST|python.*test)": "🐍",
             r"(BLOCKED|QUARANTINE)": "🚫",
             r"(ALERT|THREAT)": "🔥"}

clients = set()

def tag(line: str) -> str:
    for pattern, emoji in EMOJI_MAP.items():
        if re.search(pattern, line, re.I):
            return f"{emoji}  {line}"
    return f"📄  {line}"

async def producer(queue: asyncio.Queue):
    while True:
        line = await queue.get()
        if clients:
            await asyncio.gather(*(c.send(line) for c in clients))

class Handler(FileSystemEventHandler):
    def __init__(self, queue): self.queue, self.files = queue, {}
    def on_modified(self, event):
        if event.is_directory: return
        path = pathlib.Path(event.src_path)
        if path.suffix != ".log": return
        fp = self.files.setdefault(path, open(path, "r"))
        fp.seek(0, 2)               # jump to EOF if first time
        while (line := fp.readline()):
            asyncio.run_coroutine_threadsafe(
                self.queue.put(tag(line.rstrip())), asyncio.get_event_loop())

async def main():
    queue = asyncio.Queue()
    # start watchdog
    observer = Observer()
    handler = Handler(queue)
    for d in LOG_DIRS:
        pathlib.Path(d).mkdir(exist_ok=True)
        observer.schedule(handler, d, recursive=True)
    observer.start()

    # start WebSocket server
    async def ws_handler(websocket):
        clients.add(websocket)
        try:
            await websocket.wait_closed()
        finally:
            clients.remove(websocket)
    async with websockets.serve(ws_handler, "0.0.0.0", 8765):
        await producer(queue)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
