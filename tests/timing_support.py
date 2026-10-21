import time
from collections.abc import Callable

REPEATS = 3
# From n to 8n, linear work takes about 8 times as long and quadratic work 64 times.
LINEAR_GROWTH_LIMIT = 24


def _fastest_seconds(action: Callable[[], object]) -> float:
    fastest = float("inf")
    for _ in range(REPEATS):
        started = time.perf_counter()
        action()
        fastest = min(fastest, time.perf_counter() - started)
    return fastest


def growth(action: Callable[[int], object], size: int) -> float:
    small = _fastest_seconds(lambda: action(size))
    large = _fastest_seconds(lambda: action(8 * size))
    return large / small
