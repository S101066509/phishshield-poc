# 檔案功能：計算有限重試的退避與抖動等待，並限制失效連線清理時間。

import asyncio
import math
import random
from time import perf_counter

from app.analysis.llm.settings import LLMSettings
from app.domain.llm_models import RecoveryEvent


def retry_delay(settings: LLMSettings, attempt: int, retry_after: float | None) -> float | None:
    # Treat unparseable provider hints as a permanent recovery error, never zero wait.
    if retry_after is not None and (
        isinstance(retry_after, bool)
        or not isinstance(retry_after, (int, float))
        or not math.isfinite(retry_after)
        or retry_after < 0
        or retry_after > settings.retry_max_delay_seconds
    ):
        return None
    base = settings.retry_delay_seconds * settings.retry_backoff_multiplier ** (attempt - 1)
    delay = min(base, settings.retry_max_delay_seconds)
    delay *= random.uniform(1 - settings.retry_jitter_ratio, 1 + settings.retry_jitter_ratio)
    # Never shorten Retry-After; a hint above the cap terminates instead of retrying early.
    return min(settings.retry_max_delay_seconds, max(delay, retry_after or 0))


async def reset_connection(provider, event: RecoveryEvent, timeout: float) -> bool:
    reset = getattr(provider, "reset_connection", None)
    if not callable(reset):
        event.connection_reset = "unsupported"
        return False
    event.connection_reset = "pending"
    start = perf_counter()
    try:
        async with asyncio.timeout(timeout):
            await reset()
        if perf_counter() - start >= timeout:
            event.connection_reset = "timed_out"
            return False
        event.connection_reset = "succeeded"
        return True
    except TimeoutError:
        event.connection_reset = "timed_out"
        return False
    except asyncio.CancelledError:
        event.connection_reset = "cancelled"
        raise
    except Exception:
        event.connection_reset = "failed"
        return False
    finally:
        event.reset_latency_ms = round((perf_counter() - start) * 1000, 3)
