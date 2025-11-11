"""Boot announce monitor window + parsing engine.
    class BootAnnounceWindow:

This module contains:
- parse_tinyframe_boot_announce: permissive TinyFrame-like parser tailored for the device format
- BootAnnounceEngine: always-on accumulator that parses every UDP datagram and maintains device rows
- BootAnnounceWindow: a small UI binding to the engine to render a live table + details + raw payload

It also learns MAC addresses from ASCII "IP=..., MAC=..." messages and tries to decode a Target from
ASCII lines like "Target : 0x464F4F..." (but the Developer table intentionally hides Target now).
"""

import socket
import threading
import time
from datetime import datetime
import zlib
import subprocess
import re

import tkinter as tk
from tkinter import ttk

from haven_tftp.constants import UDP_DEFAULT_PORT


def _crc32_tf(data: bytes) -> int:
    """TinyFrame CRC32 (poly 0xedb88320), init 0xFFFFFFFF, final XOR 0xFFFFFFFF.

    Matches the CRC32 implementation in the provided C code.
    """
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _crc32_std(data: bytes) -> int:
    """Standard zlib CRC32: init 0, no final xor."""
    return zlib.crc32(data) & 0xFFFFFFFF


def _be32(b: bytes) -> int:
    return int.from_bytes(b, "big")


def parse_tinyframe_boot_announce(dat: bytes, expected_id: int | None = None):
    """Parse a TinyFrame-like packet and extract boot_announce payload.

    Parsing strategy (lenient to interop differences):
    - Expect SOF byte 0x01 then fields (ID, LEN, TYPE, HEAD_CKSUM).
    - Verify header checksum against both TinyFrame CRC32 and zlib CRC32 variations.
    - Extract data bytes of declared LEN and verify tail CRC32 similarly.
    - Interpret the first 12 bytes as (structure_version, structure_size, structure_crc32) big-endian.
    - Two payload layouts are supported:
      A) Legacy: 10 bytes of version fields: BL(maj,min), APP(maj,min,patch,build), EN(maj,min,patch,build)
      B) Extended: BL(2), APP(4), APP_CRC(4), APP_SIZE(4), EN(4), EN_CRC(4), EN_SIZE(4)

    Returns
    -------
    dict | None
        Parsed structure on success, otherwise None.
    """
    if len(dat) < 1 + 2 + 2 + 1 + 4 + 4:
        return None
    if dat[0] != 0x01:
        return None
    # Header: SOF | ID(2) | LEN(2) | TYPE(1) | HEAD_CKSUM(4)
    msg_id = int.from_bytes(dat[1:3], "big")
    msg_len = int.from_bytes(dat[3:5], "big")
    msg_type = dat[5]
    head_ck = int.from_bytes(dat[6:10], "big")
    # Verify header checksum over SOF, ID, LEN, TYPE
    head_bytes = dat[0:6]
    # Verify header CRC over SOF+ID+LEN+TYPE (TinyFrame header) using TF/zlib variants only
    calc_head_tf = _crc32_tf(head_bytes)
    calc_head_std = _crc32_std(head_bytes)
    if head_ck not in (calc_head_tf, calc_head_std):
        return None
    if expected_id is not None and msg_id != expected_id:
        return None

    # Data and tail checksum
    start = 10
    end = start + msg_len
    if len(dat) < end + 4:
        return None
    data = dat[start:end]
    ref_crc = int.from_bytes(dat[end : end + 4], "big")
    calc_tf = _crc32_tf(data)
    calc_std = _crc32_std(data)
    if ref_crc not in (calc_tf, calc_std):
        return None

    # If expected_id is provided, enforce it
    if expected_id is not None and msg_id != expected_id:
        return None

    # Interpret payload. Some devices may legitimately send an empty TinyFrame
    # (LEN=0) as a minimal boot announce. Accept it as a valid boot packet.
    if msg_len == 0:
        return {
            "type": msg_type,
            "id": msg_id,
            "structure_version": 0,
            "structure_size": 0,
            "structure_crc32": 0,
            "bootloader": (0, 0),
            "app": (0, 0, 0, 0),
            "enactor": (0, 0, 0, 0),
            "raw_data": data,
            "crc": ref_crc,
            "empty_payload": True,
        }

    # Otherwise parse the boot_announce_t structure
    if len(data) < 12 + 10:
        return None
    p = 0
    structure_version = _be32(data[p : p + 4]); p += 4
    structure_size = _be32(data[p : p + 4]); p += 4
    structure_crc32 = _be32(data[p : p + 4]); p += 4

    # Try extended layout first if enough bytes are present
    # Expected sizes: legacy = 12 + 10, extended = 12 + 26 = 38
    bl_maj = bl_min = 0
    app_maj = app_min = app_pat = app_bld = 0
    en_maj = en_min = en_pat = en_bld = 0
    app_crc = app_size = en_crc = en_size = None

    remaining = len(data) - p
    if remaining >= 26:
        # BL (2)
        bl_maj = data[p]; bl_min = data[p + 1]; p += 2
        # APP ver (4)
        app_maj, app_min, app_pat, app_bld = data[p : p + 4]; p += 4
        # APP CRC + SIZE
        app_crc = _be32(data[p : p + 4]); p += 4
        app_size = _be32(data[p : p + 4]); p += 4
        # EN ver (4)
        en_maj, en_min, en_pat, en_bld = data[p : p + 4]; p += 4
        # EN CRC + SIZE
        en_crc = _be32(data[p : p + 4]); p += 4
        en_size = _be32(data[p : p + 4]); p += 4
    else:
        # Legacy minimal layout (10 bytes)
        fields = list(data[p : p + 10])
        if len(fields) < 10:
            return None
        (bl_maj, bl_min, app_maj, app_min, app_pat, app_bld,
         en_maj, en_min, en_pat, en_bld) = fields

    return {
        "type": msg_type,
        "id": msg_id,
        "structure_version": structure_version,
        "structure_size": structure_size,
        "structure_crc32": structure_crc32,
        "bootloader": (bl_maj, bl_min),
        "app": (app_maj, app_min, app_pat, app_bld),
        "enactor": (en_maj, en_min, en_pat, en_bld),
        "app_crc": app_crc,
        "app_size": app_size,
        "enactor_crc": en_crc,
        "enactor_size": en_size,
        "raw_data": data,
        "crc": ref_crc,
    }


class BootAnnounceEngine:
    """Background parser/accumulator for boot announce frames.

    Always-on engine fed by UDP panel; maintains node table and notifies listeners.
    """

    def __init__(self):
        self.rows_data: dict[str, tuple] = {}
        self.last_raw: dict[str, bytes] = {}
        self.mac_cache: dict[str, str] = {}
        self.device_target: dict[str, str] = {}
        self._listeners: list = []
        # Progress listeners for ASCII enactor updates (ST_PROGRESS ...)
        self._progress_listeners: list = []

    def add_listener(self, fn):
        if fn not in self._listeners:
            self._listeners.append(fn)

    def remove_listener(self, fn):
        try:
            self._listeners.remove(fn)
        except ValueError:
            pass

    # Progress listener management
    def add_progress_listener(self, fn):
        if fn not in self._progress_listeners:
            self._progress_listeners.append(fn)

    def remove_progress_listener(self, fn):
        try:
            self._progress_listeners.remove(fn)
        except ValueError:
            pass

    def _mac_for_ip(self, ip: str) -> str:
        mac = self.mac_cache.get(ip)
        if mac:
            return mac
        mac = self._mac_from_arp(ip) or "unknown"
        self.mac_cache[ip] = mac
        return mac

    @staticmethod
    def _mac_from_arp(ip: str) -> str | None:
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            return None
        for line in out.splitlines():
            if ip in line:
                m = re.search(r"((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})", line)
                if m:
                    return m.group(1).lower().replace(":", "-")
        return None

    def process_datagram(self, data: bytes, addr):
        """Parse one UDP datagram and notify listeners.

        Handles three sources of information:
        - TinyFrame boot announce (binary structure)
        - ASCII utility lines (IP/MAC discovery, empty-app hints)
        - ASCII enactor progress lines (STATUS: ST_PROGRESS N/T)
        """
        # Try TinyFrame first
        parsed = parse_tinyframe_boot_announce(data, expected_id=None)

        # Also try to learn from ASCII
        try:
            text = data.decode(errors="ignore")
        except Exception:
            text = ""

        # Enactor progress: notify subscribers immediately
        if text:
            mp = re.search(r"(?:STATUS:\s*)?ST_PROGRESS\s+(\d+)\/(\d+)", text, re.IGNORECASE)
            if mp:
                try:
                    cur = int(mp.group(1)); tot = int(mp.group(2))
                except Exception:
                    cur, tot = 0, 0
                ip_txt = addr[0]
                for fn in list(self._progress_listeners):
                    try:
                        fn(ip_txt, cur, tot)
                    except Exception:
                        pass

        # IP/MAC discovery lines
        if text:
            m = re.search(r"IP\s*=\s*(\d+\.\d+\.\d+\.\d+).*?MAC\s*=\s*([0-9A-Fa-f:\-]{12,20})", text, re.IGNORECASE | re.DOTALL)
            if m:
                ip_txt = m.group(1); mac_txt = m.group(2).strip()
                self.mac_cache[ip_txt] = mac_txt
                if ip_txt in self.rows_data:
                    vals = self.rows_data[ip_txt]
                    new_vals = (vals[0], mac_txt) + vals[2:]
                    self.rows_data[ip_txt] = new_vals
                    for fn in list(self._listeners):
                        try:
                            fn(ip_txt, addr, None, mac_txt, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_vals)
                        except Exception:
                            pass

        # Learn Target (kept for internal use only)
        if text:
            mt = re.search(r"Target\s*:\s*0x([0-9A-Fa-f]{8})", text)
            if mt:
                try:
                    ip_txt = addr[0]
                    val = int(mt.group(1), 16)
                    be = val.to_bytes(4, 'big')
                    tgt = ''.join(chr(b) for b in be if 32 <= b < 127).strip()
                    if tgt:
                        self.device_target[ip_txt] = tgt
                except Exception:
                    pass

        # Tag parsed record if empty-app ASCII hint was seen (only if TinyFrame valid)
        empty_app = False
        if text and ("No valid APP_INFO" in text or "No uploaded -> boot existing app" in text):
            empty_app = True
        if parsed and empty_app:
            try:
                parsed["empty_app"] = True
            except Exception:
                pass

        # Only valid TinyFrame packets are considered boot announces
        if not parsed:
            return None

        # Publish parsed record to listeners and rows
        ip = addr[0]
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mac = self._mac_for_ip(ip)
        bl = parsed["bootloader"]; app = parsed["app"]; en = parsed["enactor"]
        tgt = self.get_target(ip)
        values = (
            ip,
            mac,
            str(parsed["type"]),
            f"0x{parsed['id']:04X}",
            tgt,
            f"{bl[0]}.{bl[1]}",
            f"{app[0]}.{app[1]}.{app[2]}.{app[3]}",
            f"{en[0]}.{en[1]}.{en[2]}.{en[3]}",
            str(parsed["structure_version"]),
            ts,
        )
        self.rows_data[ip] = values
        self.last_raw[ip] = parsed.get("raw_data", b"")
        for fn in list(self._listeners):
            try:
                fn(ip, addr, parsed, mac, ts, values)
            except Exception:
                pass
        return parsed

    def refresh_macs(self):
        # Re-resolve MACs for existing rows
        for ip, vals in list(self.rows_data.items()):
            self.mac_cache.pop(ip, None)
            mac = self._mac_for_ip(ip)
            # update second column
            new_vals = (mac,) if len(vals) < 2 else (vals[0], mac) + vals[2:]
            self.rows_data[ip] = new_vals

    def get_ips(self):
        return list(self.rows_data.keys())

    def get_target(self, ip: str) -> str:
        return self.device_target.get(ip, "")

    def get_ips(self):
        return list(self.rows_data.keys())

class BootAnnounceWindow:
    def __init__(self, root: tk.Misc, engine=None):
        self.root = root
        self.win = tk.Toplevel(root)
        self.win.title("Boot Announce Monitor")
        self.win.geometry("860x520")

        # Controls (no Start/Stop; parses from UDP panel stream)
        ctrl = ttk.Frame(self.win)
        ctrl.pack(fill=tk.X, padx=8, pady=6)

        ttk.Button(ctrl, text="CSV Export", command=self.export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Ping to ARP", command=self.ping_to_arp).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Refresh MACs", command=self.refresh_macs).pack(side=tk.LEFT, padx=4)

        # Filters for table
        filt = ttk.Frame(self.win)
        filt.pack(fill=tk.X, padx=8, pady=(0,4))
        ttk.Label(filt, text="Filter Type:").pack(side=tk.LEFT)
        self.filter_type = tk.StringVar()
        ttk.Entry(filt, textvariable=self.filter_type, width=8).pack(side=tk.LEFT, padx=4)
        ttk.Label(filt, text="Filter ID (hex):").pack(side=tk.LEFT, padx=(8,0))
        self.filter_id = tk.StringVar()
        ttk.Entry(filt, textvariable=self.filter_id, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(filt, text="Apply Filters", command=self.apply_filters).pack(side=tk.LEFT, padx=6)
        ttk.Button(filt, text="Reset", command=self.reset_filters).pack(side=tk.LEFT, padx=4)

        # Table of seen nodes
        table_frame = ttk.Frame(self.win)
        table_frame.pack(fill=tk.BOTH, expand=False, padx=8, pady=(4, 2))
        cols = ("ip", "mac", "type", "id", "boot", "app", "en", "struct", "last")
        self.table = ttk.Treeview(table_frame, columns=cols, show="headings", height=6)
        self.table.heading("ip", text="IP")
        self.table.heading("mac", text="MAC")
        self.table.heading("type", text="Type")
        self.table.heading("id", text="Msg ID")
        self.table.heading("boot", text="Bootloader")
        self.table.heading("app", text="App")
        self.table.heading("en", text="Enactor")
        self.table.heading("struct", text="Struct Ver")
        self.table.heading("last", text="Last Seen")
        self.table.column("ip", width=120)
        self.table.column("mac", width=140)
        self.table.column("type", width=60, anchor="center")
        self.table.column("id", width=80, anchor="center")
        self.table.column("boot", width=100, anchor="center")
        self.table.column("app", width=120, anchor="center")
        self.table.column("en", width=120, anchor="center")
        self.table.column("struct", width=90, anchor="center")
        self.table.column("last", width=160)
        self.table.pack(fill=tk.X, expand=False)
        self.table.bind("<<TreeviewSelect>>", self._on_select)

        # Display details
        grid = ttk.Frame(self.win)
        grid.pack(fill=tk.X, padx=8, pady=(4, 0))

        def row(r, label):
            ttk.Label(grid, text=label + ":", style="SectionTitle.TLabel").grid(row=r, column=0, sticky="w", padx=(0, 8), pady=2)
            val = ttk.Label(grid, text="-")
            val.grid(row=r, column=1, sticky="w")
            return val

        self.last_time = ttk.Label(grid, text="-")
        ttk.Label(grid, text="Last Seen:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=(2, 6))
        self.last_time.grid(row=0, column=1, sticky="w", pady=(2, 6))

        self.val_ip = row(1, "IP")
        self.val_mac = row(2, "MAC")
        self.val_type = row(3, "Type")
        self.val_id = row(4, "Msg ID")
        self.val_struct_ver = row(5, "Struct Ver")
        self.val_struct_size = row(6, "Struct Size")
        self.val_struct_crc = row(7, "Struct CRC32")
        self.val_bl = row(8, "Bootloader")
        self.val_app = row(9, "App")
        self.val_en = row(10, "Enactor")
        self.val_app_crc = row(11, "App CRC/Size")
        self.val_en_crc = row(12, "En CRC/Size")

        # Raw
        rawf = ttk.Frame(self.win)
        rawf.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.raw_text = tk.Text(rawf, height=8, wrap="none")
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        # Engine reference (background parser)
        self.engine: BootAnnounceEngine = engine or BootAnnounceEngine()
        self.engine.add_listener(self._on_engine_update)

        # No socket/thread here; fed by UDP panel via engine
        self.rows: dict[str, str] = {}
        self.mac_cache: dict[str, str] = {}
        self.last_raw: dict[str, bytes] = {}
        self.rows_data: dict[str, tuple] = {}

        # Sync initial state from engine
        self._sync_from_engine()

        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

    def _on_engine_update(self, ip: str, addr, parsed: dict | None, mac: str, ts: str, values: tuple):
        # If this is a TinyFrame update, populate details and raw
        if parsed:
            self.last_time.configure(text=f"{ts}  from {ip}:{addr[1]}")
            self.val_type.configure(text=str(parsed["type"]))
            self.val_id.configure(text=f"0x{parsed['id']:04X}")
            self.val_struct_ver.configure(text=str(parsed["structure_version"]))
            self.val_struct_size.configure(text=str(parsed["structure_size"]))
            self.val_struct_crc.configure(text=f"0x{parsed['structure_crc32']:08X}")
            bl = parsed["bootloader"]; self.val_bl.configure(text=f"{bl[0]}.{bl[1]}")
            app = parsed["app"]; self.val_app.configure(text=f"{app[0]}.{app[1]}.{app[2]}.{app[3]}")
            en = parsed["enactor"]; self.val_en.configure(text=f"{en[0]}.{en[1]}.{en[2]}.{en[3]}")
            # CRC/Size if present
            try:
                ac = parsed.get("app_crc"); asz = parsed.get("app_size")
                ec = parsed.get("enactor_crc"); esz = parsed.get("enactor_size")
                self.val_app_crc.configure(text=(f"0x{ac:08X} / {asz}" if ac is not None and asz is not None else "-"))
                self.val_en_crc.configure(text=(f"0x{ec:08X} / {esz}" if ec is not None and esz is not None else "-"))
            except Exception:
                pass
            self.val_ip.configure(text=ip)
            self.val_mac.configure(text=mac)

            raw = parsed["raw_data"].hex()
            grouped = " ".join(raw[i : i + 2] for i in range(0, len(raw), 2))
            self.raw_text.configure(state="normal")
            self.raw_text.delete("1.0", tk.END)
            self.raw_text.insert(tk.END, grouped)
            self.raw_text.configure(state="disabled")

        # Always rebuild table to reflect MAC or last-seen changes
        self._sync_from_engine()

    def _update(self, p: dict, addr):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = addr[0]
        mac = self._mac_for_ip(ip)
        self.last_time.configure(text=f"{ts}  from {ip}:{addr[1]}")
        self.val_type.configure(text=str(p["type"]))
        self.val_id.configure(text=f"0x{p['id']:04X}")
        self.val_struct_ver.configure(text=str(p["structure_version"]))
        self.val_struct_size.configure(text=str(p["structure_size"]))
        self.val_struct_crc.configure(text=f"0x{p['structure_crc32']:08X}")
        bl = p["bootloader"]; self.val_bl.configure(text=f"{bl[0]}.{bl[1]}")
        app = p["app"]; self.val_app.configure(text=f"{app[0]}.{app[1]}.{app[2]}.{app[3]}")
        en = p["enactor"]; self.val_en.configure(text=f"{en[0]}.{en[1]}.{en[2]}.{en[3]}")
        try:
            ac = p.get("app_crc"); asz = p.get("app_size")
            ec = p.get("enactor_crc"); esz = p.get("enactor_size")
            self.val_app_crc.configure(text=(f"0x{ac:08X} / {asz}" if ac is not None and asz is not None else "-"))
            self.val_en_crc.configure(text=(f"0x{ec:08X} / {esz}" if ec is not None and esz is not None else "-"))
        except Exception:
            pass
        self.val_ip.configure(text=ip)
        self.val_mac.configure(text=mac)
        # Raw
        raw = p["raw_data"].hex()
        grouped = " ".join(raw[i : i + 2] for i in range(0, len(raw), 2))
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, grouped)
        self.raw_text.configure(state="disabled")

        # Update table data and rebuild with filters
        key = ip
        self.last_raw[key] = p["raw_data"]
        tgt = self.get_target(ip)
        values = (
            ip,
            mac,
            str(p["type"]),
            f"0x{p['id']:04X}",
            f"{bl[0]}.{bl[1]}",
            f"{app[0]}.{app[1]}.{app[2]}.{app[3]}",
            f"{en[0]}.{en[1]}.{en[2]}.{en[3]}",
            str(p["structure_version"]),
            ts,
        )
        self.rows_data[key] = values
        self._rebuild_table()

    def on_close(self):
        try:
            self.engine.remove_listener(self._on_engine_update)
        except Exception:
            pass
        self.win.destroy()

    def apply_text_theme(self, cfg: dict):
        try:
            self.raw_text.configure(**cfg)
        except Exception:
            pass

    # Table filtering & rebuild helpers
    def _rebuild_table(self):
        # Clear current rows
        for iid in list(self.rows.values()):
            try:
                self.table.delete(iid)
            except Exception:
                pass
        self.rows.clear()
        ftype = (self.filter_type.get() or "").strip()
        fid = (self.filter_id.get() or "").strip().lower()
        for ip, vals in self.rows_data.items():
            v_type = vals[2]
            v_id = vals[3].lower()
            if ftype and ftype != v_type:
                continue
            if fid and fid not in v_id:
                continue
            # vals here are already without Target
            iid = self.table.insert("", tk.END, values=vals)
            self.rows[ip] = iid

    def apply_filters(self):
        self._rebuild_table()

    def reset_filters(self):
        self.filter_type.set("")
        self.filter_id.set("")
        self._rebuild_table()

    def export_csv(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("IP,MAC,Type,MsgID,Bootloader,App,Enactor,StructVer,LastSeen\n")
                for vals in self.rows_data.values():
                    line = ",".join(str(x) for x in vals)
                    f.write(line + "\n")
        except Exception:
            pass

    def refresh_macs(self):
        for ip in list(self.rows_data.keys()):
            self.mac_cache.pop(ip, None)
            _ = self._mac_for_ip(ip)
        self._rebuild_table()

    def ping_to_arp(self):
        for ip in list(self.rows_data.keys()):
            try:
                subprocess.call(["ping", "-n", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self.win.after(1000, self.refresh_macs)

    def _on_select(self, _evt=None):
        sel = self.table.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.table.item(item, "values")
        if not vals:
            return
        ip = vals[0]
        # Update details from cached row + payload
        try:
            self._set_details_from_row(ip)
        except Exception:
            pass
        # Update raw view to last payload for that IP
        raw = self.last_raw.get(ip)
        if raw is not None:
            hexs = raw.hex()
            grouped = " ".join(hexs[i : i + 2] for i in range(0, len(hexs), 2))
            self.raw_text.configure(state="normal")
            self.raw_text.delete("1.0", tk.END)
            self.raw_text.insert(tk.END, grouped)
            self.raw_text.configure(state="disabled")

    def _mac_for_ip(self, ip: str) -> str:
        # Cached lookup
        mac = self.mac_cache.get(ip)
        if mac:
            return mac
        mac = self._mac_from_arp(ip) or "unknown"
        self.mac_cache[ip] = mac
        return mac

    @staticmethod
    def _mac_from_arp(ip: str) -> str | None:
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            return None
        # Windows arp output lines: "  192.168.1.10          00-11-22-33-44-55     dynamic"
        for line in out.splitlines():
            if ip in line:
                m = re.search(r"((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})", line)
                if m:
                    return m.group(1).lower().replace(":", "-")
        return None

    def _set_details_from_row(self, ip: str):
        vals = self.rows_data.get(ip)
        if not vals:
            return
        # vals: (ip, mac, type, id, bl, app, en, struct_ver, last_seen)
        last_seen = vals[-1]
        mac = vals[1]
        v_type = vals[2]
        v_id = vals[3]
        self.last_time.configure(text=f"{last_seen}  from {ip}")
        self.val_ip.configure(text=ip)
        self.val_mac.configure(text=mac)
        self.val_type.configure(text=str(v_type))
        self.val_id.configure(text=v_id)

        raw = self.last_raw.get(ip)
        if not raw:
            return
        # Decode payload minimally to fill struct fields and versions
        try:
            p = 0
            structure_version = _be32(raw[p:p+4]); p+=4
            structure_size = _be32(raw[p:p+4]); p+=4
            structure_crc32 = _be32(raw[p:p+4]); p+=4
            self.val_struct_ver.configure(text=str(structure_version))
            self.val_struct_size.configure(text=str(structure_size))
            self.val_struct_crc.configure(text=f"0x{structure_crc32:08X}")
            if len(raw) >= p+10:
                bl_maj, bl_min, app_maj, app_min, app_pat, app_bld, en_maj, en_min, en_pat, en_bld = raw[p:p+10]
                self.val_bl.configure(text=f"{bl_maj}.{bl_min}")
                self.val_app.configure(text=f"{app_maj}.{app_min}.{app_pat}.{app_bld}")
                self.val_en.configure(text=f"{en_maj}.{en_min}.{en_pat}.{en_bld}")
        except Exception:
            pass

    def _sync_from_engine(self):
        # Copy engine state locally and rebuild table, dropping Target column if present
        src = dict(getattr(self.engine, 'rows_data', {}))
        cleaned: dict[str, tuple] = {}
        for ip, vals in src.items():
            # Engine may include Target at index 4; strip it for developer table
            if isinstance(vals, tuple) and len(vals) >= 10:
                newv = (vals[0], vals[1], vals[2], vals[3], vals[5], vals[6], vals[7], vals[8], vals[9])
            else:
                newv = vals
            cleaned[ip] = newv
        self.rows_data = cleaned
        self.last_raw = dict(getattr(self.engine, 'last_raw', {}))
        self._rebuild_table()
