from typing import TypeGuard


# bool is an int subclass, so isinstance(value, int) would accept JSON true as 1.
def is_exact_int(value: object) -> TypeGuard[int]:
    return type(value) is int


def line_number(value: object, maximum: int) -> int | None:
    return value if is_exact_int(value) and 0 < value <= maximum else None
