"""UDP terminal utilities.

This module provides a very small wrapper around a UDP socket to:
- open/close a background listener thread
- push received datagrams into a queue for GUI consumption
- call an optional `on_datagram` callback for in-app parsing (e.g., BootAnnounce)
- send one-off UDP messages

Design notes:
- The listener uses a single background thread reading recvfrom in a loop.
- When opened, we try to set SO_REUSEADDR and SO_BROADCAST (and best-effort SO_REUSEPORT)
  to play nicer with other listeners and broadcast traffic.
- We do not raise exceptions to the GUI layer from the listener thread; errors are swallowed
  (the GUI can show a user-friendly message when `open()` fails).
"""

import socket
import threading
from datetime import datetime
import binascii


class UDPTerminal:
    """Minimal UDP listener/sender with a queue bridge to the GUI.

    Parameters
    ----------
    msg_queue: queue-like
        Destination for human-readable log strings (GUI consumes these).
    on_datagram: callable | None
        Optional parser/callback called with (data: bytes, addr: (ip, port)) on each received packet.
    """

    def __init__(self, msg_queue, on_datagram=None, on_log=None):
        # Store references for logging and parsing
        self.msg_queue = msg_queue
        self.on_datagram = on_datagram
        # Optional secondary sink for human-readable log strings
        self.on_log = on_log
        # Socket and thread handles (initialized in open())
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        # Running flag for the receive loop
        self.running = False

    def open(self, port: int):
        """Bind the UDP socket and start the background listener.

        Notes
        -----
        - If binding fails, the caller should catch exceptions from this method.
        - We bind to 0.0.0.0 to receive broadcasts and packets to any local IP.
        """
        if self.running:
            return
        # Create datagram socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Best-effort options to make broadcast and multiple listeners more reliable
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        try:
            self.sock.setsockopt(getattr(socket, 'SOL_SOCKET', 0), getattr(socket, 'SO_REUSEPORT', 15), 1)
        except Exception:
            pass
        # Bind to all interfaces on the specified port
        self.sock.bind(("0.0.0.0", port))
        # Start the background listener thread
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()
        # Inform the GUI log
        self.msg_queue.put(f"Listening on port {port}\n")
        if self.on_log:
            try:
                self.on_log(f"Listening on port {port}\n")
            except Exception:
                pass

    def close(self):
        """Stop the background listener and close the socket."""
        if not self.running:
            return
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.msg_queue.put("Stopped listening\n")
        if self.on_log:
            try:
                self.on_log("Stopped listening\n")
            except Exception:
                pass

    def set_on_log(self, cb):
        """Attach or replace a secondary log sink for human-readable lines."""
        self.on_log = cb

    def send(self, ip: str, port: int, data: bytes):
        """Send a one-off UDP datagram to the given target.

        A short-lived socket is used here to avoid coupling with the listener.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(data, (ip, port))
        finally:
            s.close()

    def _listen(self):
        """Receive loop executed in a background thread.

        - Reads datagrams and forwards raw bytes to `on_datagram` if provided.
        - Also builds a concise log record with HEX + ASCII preview for the GUI.
        - Exits cleanly when the socket is closed or `running` flips to False.
        """
        assert self.sock is not None
        sock = self.sock
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                # Socket likely closed during shutdown; leave loop
                break
            # Allow the rest of the app to parse/consume the raw datagram
            try:
                if self.on_datagram:
                    self.on_datagram(data, addr)
            except Exception:
                # Do not let parsing failures kill the listener thread
                pass
            # Prepare a short human-readable log record
            ts = datetime.now().strftime("%H:%M:%S")
            hex_data = binascii.hexlify(data).decode()
            if len(hex_data) > 200:
                hex_data = hex_data[:200] + "..."
            ascii_data = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
            if len(ascii_data) > 200:
                ascii_data = ascii_data[:200] + "..."
            record = f"[{ts}] {addr[0]:<15}:{addr[1]:<5}\n  HEX: {hex_data}\n  ASCII: {ascii_data}\n\n"
            self.msg_queue.put(record)
            if self.on_log:
                try:
                    self.on_log(record)
                except Exception:
                    pass
