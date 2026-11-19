# 檔案功能：將受限解析工作移出事件迴圈，取消時通知並等待隔離程序回收。

import asyncio
from contextvars import ContextVar
from threading import Event

_CANCELLATION: ContextVar[Event | None] = ContextVar("parser_cancellation", default=None)


def cancellation_requested() -> bool:
    signal = _CANCELLATION.get()
    return signal is not None and signal.is_set()


async def run_parser_job(operation, *args):
    signal = Event()
    token = _CANCELLATION.set(signal)
    try:
        worker = asyncio.create_task(asyncio.to_thread(operation, *args))
    finally:
        _CANCELLATION.reset(token)
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        signal.set()
        # A cancelled HTTP task must not leave the parser subprocess behind.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()
        raise
