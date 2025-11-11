"""UDP Terminal panel (Developer mode).

Provides a small UDP listener with HEX/ASCII preview, filtering, and a write
popup for sending test messages. Designed for inspecting device broadcasts and
ad-hoc testing while developing.
"""

import tkinter as tk
from tkinter import ttk, filedialog
import queue
import zlib
import binascii

from haven_tftp.core.udp.terminal import UDPTerminal
from haven_tftp.gui.dialogs import UDPWritePopup
from haven_tftp.constants import UDP_DEFAULT_PORT


class UDPPanel:
    def __init__(self, root: tk.Misc, on_datagram=None, terminal=None, engine=None):
        self.root = root
        self.engine = engine
        self.frame = ttk.Frame(root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Side-by-side: controls (left) and log (right)
        self.frame.grid_columnconfigure(0, weight=0)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        left = ttk.Frame(self.frame)
        left.grid(row=0, column=0, sticky="nsw", padx=(8, 8), pady=8)
        right = ttk.Frame(self.frame)
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 8), pady=8)

        ttk.Label(left, text="UDP Terminal", style="SectionTitle.TLabel", font=("Segoe UI", 12, "bold")).pack(pady=(0, 8), anchor="w")

        port_row = ttk.Frame(left)
        port_row.pack(pady=2, fill=tk.X)
        ttk.Label(port_row, text="Port:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_row, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, str(UDP_DEFAULT_PORT))
        self.open_btn = ttk.Button(port_row, text="UDP Open", command=self.toggle_udp)
        self.open_btn.pack(side=tk.LEFT, padx=5)
        self.write_btn = ttk.Button(port_row, text="UDP Write", command=self.open_write_popup)
        self.write_btn.pack(side=tk.LEFT, padx=5)

        # Display toggle and log tools
        self.display_mode = tk.StringVar(value="Both")
        disp_row = ttk.Frame(left)
        disp_row.pack(pady=(8, 2), fill=tk.X)
        ttk.Label(disp_row, text="Display:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Combobox(
            disp_row,
            textvariable=self.display_mode,
            values=["Both", "HEX", "ASCII"],
            state="readonly",
            width=8,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(disp_row, text="Save Log", command=self.save_log).pack(side=tk.LEFT, padx=6)
        ttk.Button(disp_row, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=6)

        # Filter/search & important
        filt_row = ttk.Frame(left)
        filt_row.pack(pady=(4, 2), fill=tk.X)
        ttk.Label(filt_row, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        filt_entry = ttk.Entry(filt_row, textvariable=self.filter_var, width=18)
        filt_entry.pack(side=tk.LEFT, padx=4)
        ttk.Button(filt_row, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=4)
        ttk.Button(filt_row, text="Reset", command=self.reset_filter).pack(side=tk.LEFT, padx=4)
        self.important_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt_row, text="Important only", variable=self.important_only, command=self.apply_filter).pack(side=tk.LEFT, padx=8)

        pins = ttk.Frame(left)
        pins.pack(pady=(6, 2), fill=tk.BOTH, expand=False)
        ttk.Label(pins, text="Pinned Important:").pack(anchor="w")
        self.pins_list = tk.Listbox(pins, height=6)
        self.pins_list.pack(fill=tk.X)
        ttk.Button(pins, text="Clear Pins", command=lambda: self.pins_list.delete(0, tk.END)).pack(anchor="e", pady=(4,0))

        # TinyFrame tools (Developer): Send Module ID (0x0B) to device
        tf = ttk.LabelFrame(left, text="TinyFrame Tools")
        tf.pack(fill=tk.X, pady=(8, 4))
        r1 = ttk.Frame(tf); r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="Target IP:").pack(side=tk.LEFT)
        self.tf_ip_var = tk.StringVar(value="")
        self.tf_ip_combo = ttk.Combobox(r1, textvariable=self.tf_ip_var, width=18, state="normal")
        self.tf_ip_combo.pack(side=tk.LEFT, padx=6)
        ttk.Label(r1, text="Port:").pack(side=tk.LEFT)
        self.tf_port = tk.IntVar(value=40002)
        ttk.Entry(r1, textvariable=self.tf_port, width=8).pack(side=tk.LEFT, padx=6)
        r2 = ttk.Frame(tf); r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="Module ID (byte):").pack(side=tk.LEFT)
        self.tf_mod_id = tk.IntVar(value=1)
        ttk.Entry(r2, textvariable=self.tf_mod_id, width=6).pack(side=tk.LEFT, padx=6)
        # Options row: payload size + CRC mode
        r3 = ttk.Frame(tf); r3.pack(fill=tk.X, pady=2)
        self.tf_one_byte = tk.BooleanVar(value=False)
        ttk.Checkbutton(r3, text="Use 1-byte payload (else 4B BE)", variable=self.tf_one_byte).pack(side=tk.LEFT)
        ttk.Label(r3, text="CRC mode:").pack(side=tk.LEFT, padx=(8, 2))
        self.tf_crc_mode = tk.StringVar(value="TF")
        ttk.Combobox(r3, textvariable=self.tf_crc_mode, values=["TF", "STD"], width=6, state="readonly").pack(side=tk.LEFT)
        ttk.Button(r2, text="Send Module ID (0x0B)", command=self._send_module_id).pack(side=tk.LEFT, padx=6)

        # Populate IP dropdown from engine if available
        if self.engine is not None:
            try:
                self.engine.add_listener(self._on_engine_update)
            except Exception:
                pass
            self._refresh_tf_ips()

        # Log area
        udp_text_frame = ttk.Frame(right)
        udp_text_frame.pack(fill=tk.BOTH, expand=True)
        udp_vscroll = ttk.Scrollbar(udp_text_frame, orient="vertical")
        udp_hscroll = ttk.Scrollbar(udp_text_frame, orient="horizontal")
        self.udp_text = tk.Text(
            udp_text_frame,
            height=20,
            state="disabled",
            bg="white",
            fg="black",
            insertbackground="black",
            font=("Consolas", 10),
            wrap="none",
            yscrollcommand=udp_vscroll.set,
            xscrollcommand=udp_hscroll.set,
        )
        udp_vscroll.config(command=self.udp_text.yview)
        udp_hscroll.config(command=self.udp_text.xview)
        self.udp_text.grid(row=0, column=0, sticky="nsew")
        udp_vscroll.grid(row=0, column=1, sticky="ns")
        udp_hscroll.grid(row=1, column=0, sticky="ew")
        udp_text_frame.grid_rowconfigure(0, weight=1)
        udp_text_frame.grid_columnconfigure(0, weight=1)

        self.msg_queue: queue.Queue[str] = queue.Queue()
        if terminal is not None:
            self.terminal = terminal
            try:
                self.terminal.set_on_log(lambda s: self.msg_queue.put(s))
            except Exception:
                pass
            self.udp_running = True
            try:
                self.open_btn.config(text="Listening", state=tk.DISABLED)
            except Exception:
                pass
        else:
            self.terminal = UDPTerminal(self.msg_queue, on_datagram=on_datagram)
            self.udp_running = False
        self.log_buffer: list[str] = []
        self._poll_queue()

    def _poll_queue(self):
        try:
            while True:
                raw = self.msg_queue.get_nowait()
                msg = self._filter_display(raw)
                if not msg:
                    continue
                self._append_log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _filter_display(self, msg: str) -> str:
        mode = (self.display_mode.get() or "Both").lower()
        # Expect blocks like: header, "  HEX: ...", "  ASCII: ..."
        lines = msg.splitlines()
        if len(lines) >= 3 and lines[1].lstrip().startswith("HEX:") and lines[2].lstrip().startswith("ASCII:"):
            head = lines[0]
            hex_line = lines[1]
            ascii_line = lines[2]
            tail = "\n" if msg.endswith("\n") else ""
            if mode == "hex":
                return head + "\n" + hex_line + "\n\n"
            elif mode == "ascii":
                return head + "\n" + ascii_line + "\n\n"
            else:
                return head + "\n" + hex_line + "\n" + ascii_line + "\n\n"
        return msg

    def _is_important(self, msg: str) -> bool:
        keywords = [
            "Error",
            "DROPPED",
            "MISSING",
            "CORRUPTED",
            "TIMEOUT",
            "Size mismatch",
            "TinyFrame",  # boot announce markers
            "No valid APP_INFO",
            "No uploaded -> boot existing app",
        ]
        return any(k.lower() in msg.lower() for k in keywords)

    def _append_log(self, raw: str):
        self.log_buffer.append(raw)
        # Filtering
        if self.important_only.get() and not self._is_important(raw):
            return
        flt = (self.filter_var.get() or "").lower()
        if flt and flt not in raw.lower():
            return
        msg = self._filter_display(raw)
        self.udp_text.config(state="normal")
        self.udp_text.insert(tk.END, msg)
        self.udp_text.config(state="disabled")
        self.udp_text.see(tk.END)
        if self._is_important(raw):
            # keep a short pin text
            lines = raw.splitlines()
            if lines:
                self.pins_list.insert(tk.END, lines[0][:120])

    def toggle_udp(self):
        if not self.udp_running:
            try:
                port = int(self.port_entry.get())
            except ValueError:
                return
            try:
                self.terminal.open(port)
                self.udp_running = True
                self.open_btn.config(text="UDP Close")
            except Exception as e:
                self.msg_queue.put(f"Error: {e}\n")
        else:
            self.terminal.close()
            self.udp_running = False
        self.open_btn.config(text="UDP Open")

    def open_write_popup(self):
        UDPWritePopup(self)

    def on_close(self):
        try:
            self.terminal.close()
        except Exception:
            pass
        try:
            if self.engine is not None:
                self.engine.remove_listener(self._on_engine_update)
        except Exception:
            pass

    def save_log(self):
        path = filedialog.asksaveasfilename(
            title="Save UDP Log",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            data = self.udp_text.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
        except Exception as e:
            try:
                # If MainWindow provided a status setter via parent, use it
                self.msg_queue.put(f"Error saving log: {e}\n")
            except Exception:
                pass

    def apply_text_theme(self, cfg: dict):
        try:
            self.udp_text.configure(**cfg)
        except Exception:
            pass

    def clear_log(self):
        self.log_buffer.clear()
        self.udp_text.config(state="normal")
        self.udp_text.delete("1.0", tk.END)
        self.udp_text.config(state="disabled")

    def apply_filter(self):
        # rebuild view based on buffer
        self.udp_text.config(state="normal")
        self.udp_text.delete("1.0", tk.END)
        for raw in self.log_buffer:
            if self.important_only.get() and not self._is_important(raw):
                continue
            flt = (self.filter_var.get() or "").lower()
            if flt and flt not in raw.lower():
                continue
            msg = self._filter_display(raw)
            self.udp_text.insert(tk.END, msg)
        self.udp_text.config(state="disabled")

    def reset_filter(self):
        self.filter_var.set("")
        self.important_only.set(False)
        self.apply_filter()

    # ========== TinyFrame helpers ==========
    @staticmethod
    def _crc32_tf(data: bytes) -> int:
        # TinyFrame CRC32: init 0xFFFFFFFF, final XOR 0xFFFFFFFF
        
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        return crc ^ 0xFFFFFFFF

    @staticmethod
    def _crc32_std(data: bytes) -> int:
        # Standard zlib CRC32: init 0, no final xor
        return zlib.crc32(data) & 0xFFFFFFFF

    def _build_tf_frame(self, frame_type: int, payload: bytes, frame_id: int = 1) -> bytes:
        # Header: SOF(1)=0x01, ID(2), LEN(2), TYPE(1), CRC(4)
        sof = b"\x01"
        fid = frame_id.to_bytes(2, "big")
        ln = len(payload).to_bytes(2, "big")
        typ = bytes([frame_type & 0xFF])
        head_wo_crc = sof + fid + ln + typ
        # Use TinyFrame CRC32 (poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF) as required
        hcrc = self._crc32_tf(head_wo_crc).to_bytes(4, "big")
        pcrc = self._crc32_tf(payload).to_bytes(4, "big")
        return head_wo_crc + hcrc + payload + pcrc

    def _send_module_id(self):
        ip = (self.tf_ip_var.get() or "").strip()
        if not ip:
            self.msg_queue.put("Error: Target IP is required for Module ID command.\n")
            return
        try:
            port = int(self.tf_port.get())
        except Exception:
            port = 40002
        # Accept 0..255 and pack into 4-byte big-endian (device example uses 4B payload)
        try:
            val = int(self.tf_mod_id.get()) & 0xFF
        except Exception:
            self.msg_queue.put("Error: Module ID must be an integer 0..255.\n")
            return
        # Always send 4-byte big-endian payload with value in LSB (00 00 00 XX)
        payload = b"\x00\x00\x00" + bytes([val])
        # Build frame using TinyFrame CRC variant (matches CRC polynomial 0xEDB88320 with init/xor)
        frame = self._build_tf_frame(frame_type=0x0B, payload=payload, frame_id=1)
        try:
            self.terminal.send(ip, port, frame)
            hx = binascii.hexlify(frame).decode()
            # Decode back (big-endian) for verification in the log
            try:
                fid = int.from_bytes(frame[1:3], 'big')
                flen = int.from_bytes(frame[3:5], 'big')
                ftype = frame[5]
                hcrc = frame[6:10].hex()
                pcrc = frame[-4:].hex()
                self.msg_queue.put(
                    f"[TF] Sent Module ID 0x{val:02X} to {ip}:{port}\n"
                    f"  ID=0x{fid:04X} LEN={flen} TYPE=0x{ftype:02X} HCRC(be)={hcrc} PCRC(be)={pcrc}\n"
                    f"  HEX: {hx}\n\n"
                )
            except Exception:
                self.msg_queue.put(f"[TF] Sent Module ID 0x{val:02X} to {ip}:{port}\n  HEX: {hx}\n\n")
        except Exception as e:
            self.msg_queue.put(f"Error sending Module ID: {e}\n")

    # Engine-driven IP list for TF tools
    def _refresh_tf_ips(self):
        if self.engine is None:
            return
        try:
            ips = sorted(self.engine.get_ips())
        except Exception:
            ips = []
        try:
            self.tf_ip_combo["values"] = ips
            cur = (self.tf_ip_var.get() or '').strip()
            if not cur and ips:
                self.tf_ip_var.set(ips[0])
        except Exception:
            pass

    def _on_engine_update(self, ip: str, addr, parsed, mac, ts, values):
        # Refresh dropdown on every boot announce
        self._refresh_tf_ips()
