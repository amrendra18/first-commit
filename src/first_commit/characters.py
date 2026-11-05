DELETE_CHARACTER = "\x7f"


# A control character in an error, such as one in a file name, prints as \xNN so it
# cannot move the terminal's cursor; a newline still ends a line.
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
