"""
Async retry utility with exponential back-off.

Usage::

    from reconx.utils.retry import retry_async

    @retry_async(retries=3, base_delay=1.0, exceptions=(aiohttp.ClientError,))
    async def fetch(url):
        ...

Or inline::

    result = await retry_async(retries=3)(my_coroutine_func)(arg)
"""

from __future__ import annotations

import asyncio
import functools
import logging
import random
from typing import Any, Callable, Coroutine, Type, TypeVar

log = logging.getLogger(__name__)

_T = TypeVar("_T")


def retry_async(
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.3,
    exceptions: tuple[Type[BaseException], ...] = (Exception,),
) -> Callable:
    """
    Decorator factory: retries an async function with exponential back-off.

    Args:
        retries:    Maximum number of additional attempts (total = retries + 1).
        base_delay: Initial delay in seconds between attempts.
        max_delay:  Upper bound on the delay regardless of back-off.
        jitter:     Fraction of delay to add as random jitter (0.3 = ±30 %).
        exceptions: Tuple of exception types that trigger a retry.

    Returns:
        Decorator that wraps an async function with retry logic.
    """
    def decorator(fn: Callable[..., Coroutine[Any, Any, _T]]) -> Callable[..., Coroutine[Any, Any, _T]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> _T:
            last_exc: BaseException | None = None
            for attempt in range(retries + 1):
                try:
                    return await fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt >= retries:
                        break
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    delay += delay * jitter * (random.random() * 2 - 1)
                    delay = max(0.0, delay)
                    log.warning(
                        "%s: attempt %d/%d failed (%s). Retrying in %.1fs…",
                        fn.__qualname__, attempt + 1, retries + 1, exc, delay,
                    )
                    await asyncio.sleep(delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


async def run_with_retry(
    coro_fn: Callable[..., Coroutine[Any, Any, _T]],
    *args: Any,
    retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.3,
    exceptions: tuple[Type[BaseException], ...] = (Exception,),
    **kwargs: Any,
) -> _T:
    """
    Functional alternative to the decorator — call directly without decorating.

    Example::

        result = await run_with_retry(fetch_json, url, retries=2, base_delay=0.5)
    """
    decorated = retry_async(
        retries=retries,
        base_delay=base_delay,
        max_delay=max_delay,
        jitter=jitter,
        exceptions=exceptions,
    )(coro_fn)
    return await decorated(*args, **kwargs)
