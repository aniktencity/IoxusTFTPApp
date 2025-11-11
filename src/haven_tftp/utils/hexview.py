def format_hex(data: bytes, width: int = 16) -> str:
    """Return a simple hex+ASCII view for given bytes (placeholder).

    This is a minimal, safe implementation to avoid syntax errors during
    early development. Replace with a richer renderer later.
    """
    if not data:
        return ""

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08X}  {hex_part:<{width*3}}  |{ascii_part}|")
    return "\n".join(lines)
