"""
IOXUS BL Updater – CLI (non-interactive)

Usage examples
--------------
  # Dry-run: only list devices and staged versions
  python -m haven_tftp.cli --enable false --app /path/app.bin --enactor /path/en.bin

  # Enable updates (App first, then Enactor) and exit after 120s idle
  python -m haven_tftp.cli --enable true --app /path/app.bin --enactor /path/en.bin \
      --port 40000 --idle-timeout 120

Behavior
--------
  - Listens for boot announce packets on UDP port (default: 40000)
  - Compares device App/En version with staged files (if provided)
  - If --enable true: sends TFTP app.bin immediately within 2s of boot announce
  - After App verified on next announce, sends Enactor (if staged and mismatched)
  - Shows simple text progress; exits on Ctrl+C or when --idle-timeout is reached
"""

from __future__ import annotations

import argparse
import os
import queue
import signal
import sys
import threading
import time
import zlib

from haven_tftp.core.tftp import client as tftp_client
from haven_tftp.core.udp.terminal import UDPTerminal
from haven_tftp.gui.boot_monitor import BootAnnounceEngine


def _read_versions_from_binary(path: str):
    try:
        with open(path, "rb") as f:
            buf = f.read(4096)
        if len(buf) < 72:
            return None
        ver = buf[0:4]
        if len(ver) != 4:
            return None
        return (ver[0], ver[1], ver[2], ver[3])
    except Exception:
        return None


def _fmt_ver(v):
    if not v:
        return "-"
    return f"{v[0]}.{v[1]}.{v[2]}.{v[3]}"


def _read_file_crc_size(path: str) -> tuple[int | None, int | None]:
    """Read image CRC and size from the firmware file's embedded structure.

    If not found, returns (None, None) and the caller should fall back to version.
    """
    try:
        with open(path, "rb") as f:
            _ = f.read(4096)  # Placeholder: layout not specified
        return None, None
    except Exception:
        return None, None


class CLI:
    def __init__(self, app_path: str | None, en_path: str | None, enable: bool, port: int, idle_timeout: int):
        self.app_path = app_path
        self.en_path = en_path
        self.enable = enable
        self.port = port
        self.idle_timeout = idle_timeout

        self.app_ver = _read_versions_from_binary(app_path) if app_path else None
        self.en_ver = _read_versions_from_binary(en_path) if en_path else None

        self.engine = BootAnnounceEngine()
        self.engine.add_listener(self._on_engine)
        self.engine.add_progress_listener(self._on_enactor_progress)

        class _NullQ:
            def put(self, _):
                pass

        self.terminal = UDPTerminal(_NullQ(), on_datagram=lambda d, a: self.engine.process_datagram(d, a))
        self.last_activity = time.monotonic()

        self._await_verify: dict[str, tuple[str, tuple]] = {}
        self._ip_abort: dict[str, threading.Event] = {}

        self._prog_q: queue.Queue[tuple[str, int]] = queue.Queue()
        self._stop = threading.Event()

    def start(self):
        self._print_header()
        self.terminal.open(self.port)
        print(f"Listening on UDP {self.port}…")
        self._install_sigint()
        try:
            while not self._stop.is_set():
                # Print progress updates if any
                try:
                    ip, pct = self._prog_q.get_nowait()
                    sys.stdout.write(f"\r[{ip}] progress {pct:3d}%   ")
                    sys.stdout.flush()
                except queue.Empty:
                    pass
                # Idle timeout
                if self.idle_timeout:
                    if time.monotonic() - self.last_activity > self.idle_timeout:
                        print("\nIdle timeout reached. Exiting.")
                        break
                time.sleep(0.1)
        finally:
            try:
                self.terminal.close()
            except Exception:
                pass

    # Boot announce listener
    def _on_engine(self, ip: str, addr, parsed: dict | None, mac: str, ts: str, _values: tuple):
        self.last_activity = time.monotonic()
        if not parsed:
            return
        bl = parsed["bootloader"]; app = parsed["app"]; en = parsed["enactor"]
        print(f"\n[{ip}] BL {bl[0]}.{bl[1]} App {_fmt_ver(app)} En {_fmt_ver(en)} @ {ts}")

        if not self.enable:
            return

        # Prefer CRC-based comparison if available; fallback to version compare
        app_crc_dev = parsed.get('app_crc')
        en_crc_dev = parsed.get('enactor_crc')

        # First prefer controller (App): if device CRC missing OR mismatched
        if self.app_path:
            app_do_send = False
            app_crc, _ = _read_file_crc_size(self.app_path)
            if app_crc_dev is None:
                app_do_send = True
            elif app_crc is not None and app_crc != app_crc_dev:
                app_do_send = True
            if app_do_send:
                print(f"[{ip}] App mismatch -> sending app.bin from {os.path.basename(self.app_path)}")
                self._send(ip, self.app_path, self.app_ver, kind="app")
                # Wait for verify on next announce (by CRC if known)
                try:
                    exp_crc, _ = _read_file_crc_size(self.app_path)
                    if exp_crc is not None:
                        self._await_verify[ip] = ("app", exp_crc, 'crc')
                    elif self.app_ver:
                        self._await_verify[ip] = ("app", tuple(self.app_ver))
                except Exception:
                    pass
                return

        # If app is good, check enactor (only when device reports enactor CRC and it mismatches)
        if self.en_path:
            en_do_send = False
            if en_crc_dev is not None:
                en_crc, _ = _read_file_crc_size(self.en_path)
                if en_crc is not None and en_crc != en_crc_dev:
                    en_do_send = True
            if en_do_send:
                print(f"[{ip}] Enactor mismatch -> sending app.bin from {os.path.basename(self.en_path)}")
                self._send(ip, self.en_path, self.en_ver, kind="enactor")
                # Enactor application progress is driven by STATUS: ST_PROGRESS N/T
                return

        # Verify handling: clear when matched and optionally chain enactor
        pend = self._await_verify.get(ip)
        if pend:
            try:
                if len(pend) == 3:
                    kind, expected, mode = pend
                else:
                    kind, expected = pend
                    mode = 'ver'
            except Exception:
                kind, expected, mode = 'app', None, 'ver'
            matched = False
            if mode == 'crc':
                cur = parsed.get('app_crc') if kind == 'app' else parsed.get('enactor_crc')
                if cur is not None and expected is not None and int(cur) == int(expected):
                    matched = True
            else:
                cur = app if kind == 'app' else en
                if expected is not None and tuple(cur) == tuple(expected):
                    matched = True
            if matched:
                print(f"[{ip}] Verified {kind}.")
                try:
                    del self._await_verify[ip]
                except Exception:
                    pass
                # After App verify, consider enactor
                if kind == "app" and self.en_path:
                    # Re-evaluate enactor under CRC-first policy
                    en_do_send = False
                    en_crc_dev = parsed.get('enactor_crc')
                    if en_crc_dev is not None:
                        try:
                            en_crc, _ = _read_file_crc_size(self.en_path)
                        except Exception:
                            en_crc = None
                        if en_crc is not None and en_crc != en_crc_dev:
                            en_do_send = True
                    if en_do_send:
                        print(f"[{ip}] Enactor mismatch -> sending app.bin from {os.path.basename(self.en_path)}")
                        self._send(ip, self.en_path, self.en_ver, kind="enactor")

    def _on_enactor_progress(self, ip: str, cur: int, tot: int):
        try:
            pct = 100 if tot <= 0 else int(min(100, (cur * 100) // max(1, tot)))
            self._prog_q.put((ip, pct))
            if tot > 0 and cur >= tot:
                print(f"\n[{ip}] Enactor apply completed.")
        except Exception:
            pass

    def _send(self, ip: str, path: str, ver, kind: str):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"[{ip}] ERROR: cannot read {path}: {e}")
            return
        total = len(data)
        ev = threading.Event()
        self._ip_abort[ip] = ev

        def prog(done, tot):
            try:
                pct = 0 if tot == 0 else int((done * 100) // tot)
                self._prog_q.put((ip, pct))
            except Exception:
                pass

        ok = tftp_client.send_normal(
            ip,
            "app.bin",
            data,
            total,
            lambda s: None,
            lambda: ev.is_set(),
            include_hex=False,
            progress_cb=prog,
        )
        if not ok:
            print(f"[{ip}] {kind} transfer failed.")
        else:
            if kind == "app":
                print(f"[{ip}] App sent. Waiting for reboot to verify…")
            else:
                print(f"[{ip}] Enactor sent. Waiting for STATUS progress…")

    def _install_sigint(self):
        def _handler(_sig, _frm):
            print("\nStopping…")
            self._stop.set()
        try:
            signal.signal(signal.SIGINT, _handler)
        except Exception:
            pass


def main(argv=None):
    p = argparse.ArgumentParser(description="IOXUS BL Updater – CLI")
    p.add_argument("--app", dest="app", help="Path to Module Controller .bin", default=None)
    p.add_argument("--enactor", dest="en", help="Path to Module Enactor .bin", default=None)
    p.add_argument("--enable", dest="enable", choices=["true", "false"], default="false")
    p.add_argument("--port", dest="port", type=int, default=40000)
    p.add_argument("--idle-timeout", dest="idle", type=int, default=0, help="Exit if no activity for N seconds")
    args = p.parse_args(argv)

    cli = CLI(
        app_path=args.app,
        en_path=args.en,
        enable=(args.enable.lower() == "true"),
        port=args.port,
        idle_timeout=args.idle,
    )
    cli.start()


if __name__ == "__main__":
    main()
