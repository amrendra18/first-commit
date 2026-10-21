DELETE_CHARACTER = "\x7f"


def has_control_characters(value: str, allowed: str = "") -> bool:
    return any(
        (character < " " or character == DELETE_CHARACTER) and character not in allowed
        for character in value
    )
