import socket


def get_local_ip() -> str:
    """Best-effort local IP detection; falls back to loopback.

    Avoids network calls that could fail; uses UDP connect trick locally.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't send packets; just sets routing info
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"
