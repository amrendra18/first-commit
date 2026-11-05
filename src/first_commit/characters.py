DELETE_CHARACTER = "\x7f"


def escaped_controls(text: str) -> str:
    return "".join(
        f"\\x{ord(character):02x}"
        if has_control_characters(character, allowed="\n")
        else character
        for character in text
    )


def has_control_characters(value: str, allowed: str = "") -> bool:
    return any(
        (character < " " or character == DELETE_CHARACTER) and character not in allowed
        for character in value
    )
