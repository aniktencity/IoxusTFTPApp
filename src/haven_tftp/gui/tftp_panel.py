"""Developer TFTP panel.

This panel provides a manual TFTP sender with several failure simulation modes and
an optional TFTP server for WRQ (write) handling. It also integrates with the
BootAnnounceEngine to auto-populate the device dropdown.

Key UX behaviors:
- Normal send (always sends as filename \"app.bin\" regardless of source file)
- Abort button that responds promptly via a shared `abort_flag`
- Failure simulations: out-of-order, duplicates, wrong block numbers, truncated, timeout, packet loss
- Log filters and a small \"Pinned Important\" list for quick scanning
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading
import queue
import binascii

from haven_tftp.utils.net import get_local_ip
from haven_tftp.gui.tooltips import ToolTip
from haven_tftp.core.tftp.server import TFTPServer
from haven_tftp.core.tftp import client as tftp_client
from haven_tftp.constants import DEFAULT_TARGET_IP


class TFTPPanel:
    def __init__(self, root: tk.Misc, set_status=None, engine=None):
        self.root = root
        self.set_status = set_status or (lambda s: None)
        self.engine = engine
        self.frame = ttk.Frame(root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Split layout
        self.frame.grid_columnconfigure(0, weight=0)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        left = ttk.Frame(self.frame)
        left.grid(row=0, column=0, sticky="nsw", padx=(8, 8), pady=8)
        right = ttk.Frame(self.frame)
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 8), pady=8)

        ttk.Label(left, text="TFTP", style="SectionTitle.TLabel", font=("Segoe UI", 12, "bold")).pack(pady=(0, 8), anchor="w")

        mode_frame = ttk.Frame(left)
        mode_frame.pack(pady=5, fill=tk.X)
        ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT, padx=5)
        self.mode_var = tk.StringVar(value="send")
        self.send_radio = ttk.Radiobutton(
            mode_frame,
            text="Send",
            variable=self.mode_var,
            value="send",
            command=self.switch_mode,
        )
        self.send_radio.pack(side=tk.LEFT, padx=5)
        self.listen_radio = ttk.Radiobutton(
            mode_frame,
            text="Listen",
            variable=self.mode_var,
            value="listen",
            command=self.switch_mode,
        )
        self.listen_radio.pack(side=tk.LEFT, padx=5)

        ip_frame = ttk.Frame(left)
        ip_frame.pack(pady=5)
        self.ip_label = ttk.Label(ip_frame, text="Target IP:")
        self.ip_label.pack(side=tk.LEFT)
        # Start empty; will auto-populate from first BootAnnounce via engine
        self.target_ip_var = tk.StringVar(value="")
        self.ip_combo = ttk.Combobox(ip_frame, textvariable=self.target_ip_var, width=20, state="normal")
        self.ip_combo.pack(side=tk.LEFT, padx=5)
        self.ip_display = ttk.Label(ip_frame, text="", width=20)

        # Send controls
        self.send_frame = ttk.Frame(left)
        self.send_frame.pack(pady=5)
        file_frame = ttk.Frame(self.send_frame)
        file_frame.pack(pady=5)
        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        self.file_entry = ttk.Entry(file_frame, width=40)
        self.file_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        ttk.Label(self.send_frame, text="Send", font=("Segoe UI", 10, "bold")).pack(pady=(10, 2))

        btn_frame = ttk.Frame(self.send_frame)
        btn_frame.pack(pady=5)
        self.normal_send_btn = ttk.Button(btn_frame, text="TFTP Send", command=self.normal_send_tftp)
        self.normal_send_btn.pack(side=tk.LEFT, padx=5)

        # Log options and Save Log
        options_frame = ttk.Frame(self.send_frame)
        options_frame.pack(pady=2)
        self.show_hex_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Show HEX in log",
            variable=self.show_hex_var,
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            options_frame,
            text="Save Log",
            command=self.save_log,
        ).pack(side=tk.LEFT, padx=8)
        ttk.Button(
            options_frame,
            text="Clear Log",
            command=self.clear_log,
        ).pack(side=tk.LEFT, padx=4)

        # Log tools: filter + important
        tools = ttk.Frame(left)
        tools.pack(pady=(6, 2), fill=tk.X)
        ttk.Label(tools, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        ttk.Entry(tools, textvariable=self.filter_var, width=18).pack(side=tk.LEFT, padx=4)
        ttk.Button(tools, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=4)
        ttk.Button(tools, text="Reset", command=self.reset_filter).pack(side=tk.LEFT, padx=4)
        self.important_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(tools, text="Important only", variable=self.important_only, command=self.apply_filter).pack(side=tk.LEFT, padx=8)
        # Auto-restart checkbox (user option)
        self.auto_restart_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tools, text="Auto-restart after abort", variable=self.auto_restart_var).pack(side=tk.LEFT, padx=8)

        pins = ttk.Frame(left)
        pins.pack(pady=(4, 2), fill=tk.BOTH, expand=False)
        ttk.Label(pins, text="Pinned Important:").pack(anchor="w")
        self.pins_list = tk.Listbox(pins, height=6)
        self.pins_list.pack(fill=tk.X)
        ttk.Button(pins, text="Clear Pins", command=lambda: self.pins_list.delete(0, tk.END)).pack(anchor="e", pady=(4,0))

        ttk.Label(self.send_frame, text="Failure Simulations:").pack(pady=(10, 2))

        btn_frame2 = ttk.Frame(self.send_frame)
        btn_frame2.pack(pady=2)
        self.fail_outoforder_btn = ttk.Button(btn_frame2, text="Out-of-Order", command=self.failure_out_of_order, width=12)
        self.fail_outoforder_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_outoforder_btn, "Sends blocks 1,2,4,3,5,6... to test handling of misordered packets")

        self.fail_duplicate_btn = ttk.Button(btn_frame2, text="Duplicates", command=self.failure_duplicate, width=12)
        self.fail_duplicate_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_duplicate_btn, "Sends some blocks twice to test duplicate detection")

        self.fail_wrongnum_btn = ttk.Button(btn_frame2, text="Wrong Block #", command=self.failure_wrong_numbers, width=12)
        self.fail_wrongnum_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_wrongnum_btn, "Uses incorrect block numbering to test validation")

        btn_frame3 = ttk.Frame(self.send_frame)
        btn_frame3.pack(pady=2)
        self.fail_truncated_btn = ttk.Button(btn_frame3, text="Truncated", command=self.failure_truncated, width=12)
        self.fail_truncated_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_truncated_btn, "Stops after sending 60% of file to test incomplete transfers")

        self.fail_timeout_btn = ttk.Button(btn_frame3, text="Timeout", command=self.failure_timeout, width=12)
        self.fail_timeout_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_timeout_btn, "Pauses 10 seconds mid-transfer to test timeout handling")

        self.fail_pktloss_btn = ttk.Button(btn_frame3, text="Packet Loss", command=self.failure_packet_loss, width=12)
        self.fail_pktloss_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.fail_pktloss_btn, "Randomly drops ~30% of packets to test loss detection")

        self.swap_send_btn = ttk.Button(btn_frame3, text="Data Swap", command=self.swap_send_tftp, width=12)
        self.swap_send_btn.pack(side=tk.LEFT, padx=3)
        ToolTip(self.swap_send_btn, "Swaps two random bytes in file data to test data corruption detection")

        # Listen controls
        self.listen_frame = ttk.Frame(left)
        output_frame = ttk.Frame(self.listen_frame)
        output_frame.pack(pady=5)
        ttk.Label(output_frame, text="Output File:").pack(side=tk.LEFT)
        self.output_entry = ttk.Entry(output_frame, width=40)
        self.output_entry.pack(side=tk.LEFT, padx=5)
        self.output_entry.insert(0, "received.bin")
        listen_btn_frame = ttk.Frame(self.listen_frame)
        listen_btn_frame.pack(pady=10)
        self.start_listen_btn = ttk.Button(listen_btn_frame, text="Start Listen", command=self.toggle_listen)
        self.start_listen_btn.pack(side=tk.LEFT, padx=5)

        # Abort + progress
        self.abort_frame = ttk.Frame(left)
        self.abort_btn = ttk.Button(self.abort_frame, text="Abort Send", command=self.abort_send)
        self.abort_btn.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(left, mode="indeterminate", length=200)

        # Text area
        self.tftp_text_frame = ttk.Frame(right)
        self.tftp_text_frame.pack(fill=tk.BOTH, expand=True)
        tftp_vscroll = ttk.Scrollbar(self.tftp_text_frame, orient="vertical")
        tftp_hscroll = ttk.Scrollbar(self.tftp_text_frame, orient="horizontal")
        self.tftp_text = tk.Text(
            self.tftp_text_frame,
            height=20,
            state="disabled",
            bg="white",
            fg="black",
            insertbackground="black",
            font=("Consolas", 10),
            wrap="none",
            yscrollcommand=tftp_vscroll.set,
            xscrollcommand=tftp_hscroll.set,
        )
        tftp_vscroll.config(command=self.tftp_text.yview)
        tftp_hscroll.config(command=self.tftp_text.xview)
        self.tftp_text.grid(row=0, column=0, sticky="nsew")
        tftp_vscroll.grid(row=0, column=1, sticky="ns")
        tftp_hscroll.grid(row=1, column=0, sticky="ew")
        self.tftp_text_frame.grid_rowconfigure(0, weight=1)
        self.tftp_text_frame.grid_columnconfigure(0, weight=1)

        # State
        self.sending = False
        self.abort_flag = False
        self.tftp_msg_queue: queue.Queue[str] = queue.Queue()
        self.tftp_mode = "send"
        self.tftp_listening = False
        self.server: TFTPServer | None = None
        self.tftp_thread: threading.Thread | None = None
        self._stop_sending_flag = False
        self._restart_pending = False
        self._last_send = None  # (fn, ip, filename_req, file_data, total_bytes, kwargs)

        self._poll_tftp_queue()
        self.switch_mode()
        self.tftp_log_buffer: list[str] = []
        # Subscribe to engine for device list updates
        if hasattr(self, 'engine') and self.engine:
            try:
                self._refresh_device_list()
                self.engine.add_listener(self._on_engine_update)
            except Exception:
                pass

    def _log(self, msg: str):
        self.tftp_msg_queue.put(msg)

    def _poll_tftp_queue(self):
        try:
            while True:
                msg = self.tftp_msg_queue.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_tftp_queue)
        if self._stop_sending_flag:
            self._stop_sending_flag = False
            self.stop_sending()
            if self._restart_pending and self._last_send and not self.sending:
                self._restart_pending = False
                fn, ip, filename_req, file_data, total_bytes, kwargs = self._last_send
                self._log("Restarting transfer...\n")
                self.start_sending()
                self.tftp_thread = threading.Thread(
                    target=self._run_sender,
                    args=(fn, ip, filename_req, file_data, total_bytes),
                    kwargs=kwargs,
                    daemon=True,
                )
                self.tftp_thread.start()

    def switch_mode(self):
        mode = self.mode_var.get()
        self.tftp_mode = mode
        if mode == "send":
            self.send_frame.pack(pady=5)
            self.listen_frame.pack_forget()
            self.ip_label.config(text="Target IP:")
            self.ip_display.pack_forget()
            if not self.ip_combo.winfo_ismapped():
                self.ip_combo.pack(side=tk.LEFT, padx=5)
        else:
            self.send_frame.pack_forget()
            self.listen_frame.pack(pady=5)
            self.ip_label.config(text="Listen IP:")
            local_ip = get_local_ip()
            self.ip_combo.pack_forget()
            self.ip_display.config(text=local_ip)
            self.ip_display.pack(side=tk.LEFT, padx=5)

    def toggle_listen(self):
        if not self.tftp_listening:
            ip = self.ip_display.cget("text") or get_local_ip()
            filename = self.output_entry.get()
            try:
                self.server = TFTPServer(ip, filename, self.tftp_msg_queue)
                self.server.start()
                self.tftp_listening = True
                self.start_listen_btn.config(text="Stop Listen")
                self.send_radio.config(state="disabled")
                self.listen_radio.config(state="disabled")
                self.set_status(f"TFTP listening on {ip}:69 -> {filename}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            if self.server:
                self.server.stop()
                self.server = None
            self.tftp_listening = False
            self.start_listen_btn.config(text="Start Listen")
            self.send_radio.config(state="normal")
            self.listen_radio.config(state="normal")
            self.set_status("TFTP listening stopped")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def start_sending(self):
        self.sending = True
        self.abort_flag = False
        self.normal_send_btn.config(state="disabled")
        self.swap_send_btn.config(state="disabled")
        self.fail_outoforder_btn.config(state="disabled")
        self.fail_duplicate_btn.config(state="disabled")
        self.fail_wrongnum_btn.config(state="disabled")
        self.fail_truncated_btn.config(state="disabled")
        self.fail_timeout_btn.config(state="disabled")
        self.fail_pktloss_btn.config(state="disabled")
        self.abort_frame.pack(pady=5)
        self.progress.pack(pady=5)
        self.progress.start()
        self._log("Sending...\n")
        self.send_radio.config(state="disabled")
        self.listen_radio.config(state="disabled")
        self.set_status("TFTP sending...")

    def stop_sending(self):
        self._log("Cleaning up send UI...\n")
        self.sending = False
        self.normal_send_btn.config(state="normal")
        self.swap_send_btn.config(state="normal")
        self.fail_outoforder_btn.config(state="normal")
        self.fail_duplicate_btn.config(state="normal")
        self.fail_wrongnum_btn.config(state="normal")
        self.fail_truncated_btn.config(state="normal")
        self.fail_timeout_btn.config(state="normal")
        self.fail_pktloss_btn.config(state="normal")
        self.abort_frame.pack_forget()
        self.progress.stop()
        self.progress.pack_forget()
        self.send_radio.config(state="normal")
        self.listen_radio.config(state="normal")
        self.set_status("Idle")

    def abort_send(self):
        self.abort_flag = True
        self._log("Aborting send...\n")
        self.set_status("TFTP abort requested")
        # Restart only if user enabled it
        self._restart_pending = bool(self.auto_restart_var.get())

    def _run_sender(self, fn, ip, filename_req, file_data, total_bytes, **kwargs):
        try:
            ok = fn(
                ip,
                filename_req,
                file_data,
                total_bytes,
                self._log,
                lambda: self.abort_flag,
                **kwargs,
            )
            # Pin success
            if ok:
                from datetime import datetime
                ts = datetime.now().strftime("%H:%M:%S")
                self.pins_list.insert(tk.END, f"[OK] TFTP {ip} {filename_req} {total_bytes}B @ {ts}")
        except Exception as e:
            if self.abort_flag:
                self._log("Upload aborted\n")
            else:
                self._log(f"Error: {e}\n")
        finally:
            self._stop_sending_flag = True

    def _prepare_send(self):
        ip = self.target_ip_var.get().strip()
        filename = self.file_entry.get().strip()
        if not ip or not filename or not os.path.exists(filename):
            messagebox.showerror("Error", "Invalid IP or file")
            return None
        with open(filename, "rb") as f:
            file_data = bytearray(f.read())
        # Always send as app.bin regardless of source filename
        return ip, "app.bin", file_data, len(file_data)

    def normal_send_tftp(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting normal TFTP upload to {ip}: {filename_req}\n")
        self._last_send = (tftp_client.send_normal, ip, filename_req, file_data, total_bytes, {"include_hex": bool(self.show_hex_var.get())})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_normal, ip, filename_req, file_data, total_bytes),
            kwargs={"include_hex": bool(self.show_hex_var.get())},
            daemon=True,
        )
        self.tftp_thread.start()

    def swap_send_tftp(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        if total_bytes > 1:
            import random
            pos1 = random.randint(total_bytes // 4, 3 * total_bytes // 4)
            pos2 = random.randint(total_bytes // 4, 3 * total_bytes // 4)
            while pos2 == pos1:
                pos2 = random.randint(total_bytes // 4, 3 * total_bytes // 4)
            file_data[pos1], file_data[pos2] = file_data[pos2], file_data[pos1]
            self._log(f"Swapped bytes at positions {pos1} and {pos2}\n")
        self.start_sending()
        self._log(f"Starting swap TFTP upload to {ip}: {filename_req}\n")
        self._last_send = (tftp_client.send_normal, ip, filename_req, file_data, total_bytes, {"include_hex": bool(self.show_hex_var.get())})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_normal, ip, filename_req, file_data, total_bytes),
            kwargs={"include_hex": bool(self.show_hex_var.get())},
            daemon=True,
        )
        self.tftp_thread.start()
    def failure_out_of_order(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting out-of-order TFTP upload to {ip}: {filename_req}\n")
        self._log(f"Starting out-of-order TFTP upload to {ip}: {filename_req}\\n")

        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_out_of_order, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()

    def failure_duplicate(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting duplicate blocks TFTP upload to {ip}: {filename_req}\n")
        self._last_send = (tftp_client.send_duplicates, ip, filename_req, file_data, total_bytes, {})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_duplicates, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()
    def failure_wrong_numbers(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting wrong block numbers TFTP upload to {ip}: {filename_req}")
        self._log(f"Starting wrong block numbers TFTP upload to {ip}: {filename_req}\\n")
        self._last_send = (tftp_client.send_wrong_block_numbers, ip, filename_req, file_data, total_bytes, {})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_wrong_block_numbers, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()

    def failure_truncated(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting truncated TFTP upload to {ip}: {filename_req}")
        self._log(f"Starting truncated TFTP upload to {ip}: {filename_req}\\n")
        self._last_send = (tftp_client.send_truncated, ip, filename_req, file_data, total_bytes, {})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_truncated, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()

    def failure_timeout(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting timeout TFTP upload to {ip}: {filename_req}")
        self._log(f"Starting timeout TFTP upload to {ip}: {filename_req}\\n")
        self._last_send = (tftp_client.send_timeout_pause, ip, filename_req, file_data, total_bytes, {})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_timeout_pause, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()

    def failure_packet_loss(self):
        if self.sending:
            return
        prep = self._prepare_send()
        if not prep:
            return
        ip, filename_req, file_data, total_bytes = prep
        self.start_sending()
        self._log(f"Starting packet loss TFTP upload to {ip}: {filename_req}")
        self._log(f"Starting packet loss TFTP upload to {ip}: {filename_req}\\n")
        self._last_send = (tftp_client.send_packet_loss, ip, filename_req, file_data, total_bytes, {})
        self.tftp_thread = threading.Thread(
            target=self._run_sender,
            args=(tftp_client.send_packet_loss, ip, filename_req, file_data, total_bytes),
            daemon=True,
        )
        self.tftp_thread.start()

    def on_close(self):
        # Stop server
        if self.tftp_listening and self.server:
            try:
                self.server.stop()
            except Exception:
                pass
        # Abort sending
        if self.sending:
            self.abort_send()
        try:
            if self.engine:
                self.engine.remove_listener(self._on_engine_update)
        except Exception:
            pass

    def save_log(self):
        from tkinter import filedialog

        path = filedialog.asksaveasfilename(
            title="Save TFTP Log",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            data = self.tftp_text.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
        except Exception as e:
            self._log(f"Error saving log: {e}")
            self._log(f"Error saving log: {e}\n")

    def _is_important(self, msg: str) -> bool:
        keywords = ["Error", "DROPPED", "MISSING", "CORRUPTED", "SIZE MISMATCH", "TIMEOUT", "WARN", "WARNING"]
        low = msg.lower()
        return any(k.lower() in low for k in keywords)
    def _append_log(self, raw: str):
        self.tftp_log_buffer.append(raw)
        if self.important_only.get() and not self._is_important(raw):
            return
        flt = (self.filter_var.get() or "").lower()
        if flt and flt not in raw.lower():
            return
        self.tftp_text.config(state="normal")
        self.tftp_text.insert(tk.END, raw)
        self.tftp_text.config(state="disabled")
        self.tftp_text.see(tk.END)
        if self._is_important(raw):
            line = raw.splitlines()[0] if raw else raw
            self.pins_list.insert(tk.END, (line or "")[:120])

    def clear_log(self):
        self.tftp_log_buffer.clear()
        self.tftp_text.config(state="normal")
        self.tftp_text.delete("1.0", tk.END)
        self.tftp_text.config(state="disabled")

    def apply_filter(self):
        self.tftp_text.config(state="normal")
        self.tftp_text.delete("1.0", tk.END)
        flt = (self.filter_var.get() or "").lower()
        for raw in self.tftp_log_buffer:
            if self.important_only.get() and not self._is_important(raw):
                continue
            if flt and flt not in raw.lower():
                continue
            self.tftp_text.insert(tk.END, raw)
        self.tftp_text.config(state="disabled")

    def reset_filter(self):
        self.filter_var.set("")
        self.important_only.set(False)
        self.apply_filter()

    # Engine device list updates
    def _refresh_device_list(self):
        if not self.engine:
            return
        try:
            ips = sorted(self.engine.get_ips())
        except Exception:
            ips = []
        self.ip_combo["values"] = ips
        cur = (self.target_ip_var.get() or '').strip()
        if not cur and ips:
            self.target_ip_var.set(ips[0])

    def _on_engine_update(self, ip: str, addr, parsed, mac, ts, values):
        self._refresh_device_list()

    def apply_text_theme(self, cfg: dict):
        try:
            self.tftp_text.configure(**cfg)
        except Exception:
            pass





