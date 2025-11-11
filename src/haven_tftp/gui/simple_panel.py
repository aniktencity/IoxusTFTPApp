import tkinter as tk
from tkinter import ttk, filedialog
import threading
import queue
import os
import time

from haven_tftp.core.tftp import client as tftp_client


def _decode_target_le_u32_to_text(le_bytes: bytes) -> str:
    try:
        if len(le_bytes) != 4:
            return ""
        val = int.from_bytes(le_bytes, "little")
        be = val.to_bytes(4, "big")
        txt = "".join(chr(b) for b in be if 32 <= b < 127).strip()
        return txt
    except Exception:
        return ""


def _read_versions_from_binary(path: str):
    """Read fw_metadata_t at start of binary.

    typedef struct __attribute__((packed)) {
        uint8_t  ver_major;
        uint8_t  ver_minor;
        uint8_t  ver_patch;
        uint8_t  ver_build;
        char     cert_key[64];
        uint32_t target; // e.g., 'F407' or 'L072' stored as ASCII in a u32
    } fw_metadata_t;

    Returns: (version_tuple, target_text) or (None, "").
    """
    try:
        with open(path, "rb") as f:
            buf = f.read(4096)
        if len(buf) < 72:
            return None, ""
        # Scan the first 4 KB for a plausible fw_metadata_t
        best = None
        for pos in range(0, min(len(buf) - 72, 4096) + 1, 4):
            ver = buf[pos:pos+4]
            tgt_bytes = buf[pos+68:pos+72]
            tgt = _decode_target_le_u32_to_text(tgt_bytes)
            if not tgt:
                continue
            if tgt in ("F407", "L072") or tgt.isalnum():
                best = (pos, ver, tgt)
                break
        if not best:
            # Fallback to position 0
            pos = 0
            ver = buf[0:4]
            tgt = _decode_target_le_u32_to_text(buf[68:72])
        else:
            pos, ver, tgt = best
        if len(ver) != 4:
            return None, ""
        return (ver[0], ver[1], ver[2], ver[3]), tgt
    except Exception:
        return None, ""


def _read_file_crc_size(path: str) -> tuple[int | None, int | None]:
    """Read image CRC and size from app_info_t embedded at the file start.

    struct app_info_t (packed):
      +0   ver[4]
      +4   cert_key[64]
      +68  target (u32, little-endian)
      +72  image_crc (u32, little-endian)
      +76  image_size (u32/size_t, little-endian)
    We scan first 4KB in 4-byte steps for a plausible target; else fall back to +0.
    """
    try:
        with open(path, 'rb') as f:
            buf = f.read(4096)
        if len(buf) < 80:
            return None, None
        # Find plausible metadata block
        best_pos = None
        for pos in range(0, min(len(buf) - 80, 4096) + 1, 4):
            tgt_le = int.from_bytes(buf[pos+68:pos+72], 'little', signed=False)
            be = tgt_le.to_bytes(4, 'big')
            tgt_txt = ''.join(chr(b) for b in be if 32 <= b < 127).strip()
            if tgt_txt and (tgt_txt in ("F407", "L072") or tgt_txt.isalnum()):
                best_pos = pos
                break
        if best_pos is None:
            best_pos = 0
        crc = int.from_bytes(buf[best_pos+72:best_pos+76], 'little', signed=False)
        size = int.from_bytes(buf[best_pos+76:best_pos+80], 'little', signed=False)
        return crc, size
    except Exception:
        return None, None


class SimpleUpdatePanel:
    """
    Non-technical "Simple" dashboard for multi-device updates.

    Responsibilities
    - Present a clean, two-file staging UI (Module Controller + Module Enactor)
    - Show a scrollable grid of devices with per-tile status and progress bars
    - Auto-queue updates based on version mismatches (App first, then Enactor)
    - Track Enactor apply progress via UDP STATUS: ST_PROGRESS messages
    - Verify success on next BootAnnounce (tile shows "Verified ✓")
    - Limit parallel updates via a simple in-process queue
    """

    def __init__(self, root: tk.Misc, engine, log_func=None):
        self.root = root
        self.engine = engine
        self.log = log_func or (lambda s: None)

        self.frame = ttk.Frame(root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.auto_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Waiting for devices...")

        # Visual style for a polished, management-friendly look
        self._init_styles()

        # Header banner
        header = ttk.Frame(self.frame, style="SimpleHeader.TFrame")
        header.pack(fill=tk.X)
        try:
            from haven_tftp.constants import APP_VERSION
        except Exception:
            APP_VERSION = ""
        title_text = "IOXUS BL Updater" + (f" v{APP_VERSION}" if APP_VERSION else "")
        ttk.Label(header, text=title_text, style="SimpleHeader.TLabel").pack(side=tk.LEFT, padx=16, pady=12)
        self.header_status = ttk.Label(header, text="Auto Update: ON", style="HeaderStatus.TLabel")
        self.header_status.pack(side=tk.RIGHT, padx=16, pady=12)

        # Top controls row
        top = ttk.Frame(self.frame)
        top.pack(fill=tk.X, padx=16, pady=12)
        ttk.Label(top, text="Auto Update:", style="Accent.TLabel").pack(side=tk.LEFT)
        chk = ttk.Checkbutton(top, variable=self.auto_var, command=self._update_header_status)
        chk.pack(side=tk.LEFT, padx=8)
        ttk.Label(top, textvariable=self.status_var).pack(side=tk.LEFT, padx=16)
        # Concurrency selector
        ttk.Label(top, text="Max updates (parallel):").pack(side=tk.LEFT, padx=(24,4))
        self.max_concurrency_var = tk.IntVar(value=2)
        ttk.Combobox(top, values=[1,2,3,4], width=3, state="readonly", textvariable=self.max_concurrency_var).pack(side=tk.LEFT)

        files = ttk.LabelFrame(self.frame, text="Update Files", style="Card.TLabelframe")
        files.pack(fill=tk.X, padx=16, pady=8)

        # App file
        r1 = ttk.Frame(files); r1.pack(fill=tk.X, pady=6)
        ttk.Label(r1, text="Module Controller File:", style="Bold.TLabel").pack(side=tk.LEFT)
        self.app_path = tk.StringVar()
        ttk.Entry(r1, textvariable=self.app_path, width=60).pack(side=tk.LEFT, padx=8)
        # Use tk.Button to ensure color visibility across themes on Windows
        self.app_browse_btn = tk.Button(r1, text="Browse", command=self._pick_app)
        self.app_browse_btn.pack(side=tk.LEFT)
        self.app_ver_lbl = ttk.Label(r1, text="(ver: -)")
        self.app_ver_lbl.pack(side=tk.LEFT, padx=8)

        # Enactor file
        r2 = ttk.Frame(files); r2.pack(fill=tk.X, pady=6)
        ttk.Label(r2, text="Module Enactor File:", style="Bold.TLabel").pack(side=tk.LEFT)
        self.en_path = tk.StringVar()
        ttk.Entry(r2, textvariable=self.en_path, width=60).pack(side=tk.LEFT, padx=8)
        self.en_browse_btn = tk.Button(r2, text="Browse", command=self._pick_en)
        self.en_browse_btn.pack(side=tk.LEFT)
        self.en_ver_lbl = ttk.Label(r2, text="(ver: -)")
        self.en_ver_lbl.pack(side=tk.LEFT, padx=8)

        # Device grid (scrollable)
        gridf = ttk.LabelFrame(self.frame, text="Devices", style="Card.TLabelframe")
        gridf.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)
        self._grid_canvas = tk.Canvas(gridf, highlightthickness=0, borderwidth=0)
        vs = ttk.Scrollbar(gridf, orient="vertical", command=self._grid_canvas.yview)
        self._tiles_host = ttk.Frame(self._grid_canvas)
        self._tiles_host.bind("<Configure>", lambda e: self._grid_canvas.configure(scrollregion=self._grid_canvas.bbox("all")))
        self._grid = self._grid_canvas.create_window((0,0), window=self._tiles_host, anchor="nw")
        self._grid_canvas.configure(yscrollcommand=vs.set)
        self._grid_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.tiles: dict[str, dict] = {}

        # Single-device info (for last update) retained but de-emphasized
        dev = ttk.LabelFrame(self.frame, text="Last Device", style="Card.TLabelframe")
        dev.pack(fill=tk.X, padx=16, pady=8)
        self.dev_ip = ttk.Label(dev, text="IP: -"); self.dev_ip.pack(anchor="w", padx=6, pady=2)
        self.dev_bl = ttk.Label(dev, text="Bootloader: -"); self.dev_bl.pack(anchor="w", padx=6, pady=2)
        self.dev_app = ttk.Label(dev, text="App: -"); self.dev_app.pack(anchor="w", padx=6, pady=2)
        self.dev_en = ttk.Label(dev, text="Enactor: -"); self.dev_en.pack(anchor="w", padx=6, pady=2)

        # Progress
        prog = ttk.Frame(self.frame)
        prog.pack(fill=tk.X, padx=16, pady=10)
        self.progress = ttk.Progressbar(prog, mode="determinate", length= max(240, min(700, int((self.root.winfo_screenwidth() or 1280) * 0.35))), style="Success.Horizontal.TProgressbar")
        self.progress.pack(side=tk.LEFT)
        self.progress['value'] = 0

        # Log area (minimal)
        logf = ttk.LabelFrame(self.frame, text="Activity", style="Card.TLabelframe")
        logf.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0,16))
        self.log_text = tk.Text(logf, height=10, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Observers
        self.engine.add_listener(self._on_engine)
        # Multi-device job state
        from collections import deque
        self._pending = deque()
        self._active: set[str] = set()
        self._jobs_lock = threading.Lock()
        # Await verification after an update: ip -> (kind, expected_version_tuple)
        self._await_verify: dict[str, tuple[str, tuple]] = {}
        self.sending = False
        # Background progress pump (thread-safe)
        self._prog_q: queue.Queue[int] = queue.Queue()
        self._poll_progress()
        # Optional local UDP listener used during enactor apply if background listener failed
        self._local_udp = None
        # Per-IP abort flags so a reboot/announce cancels in-flight transfers
        self._ip_abort = {}
        # Debounce map for per-IP reset events (avoid thrashing on bursty announces)
        self._last_reset_at: dict[str, float] = {}

    def destroy(self):
        try:
            self.engine.remove_listener(self._on_engine)
        except Exception:
            pass

    def apply_text_theme(self, cfg: dict):
        try:
            self.log_text.configure(**cfg)
        except Exception:
            pass

    def _pick_app(self):
        p = filedialog.askopenfilename()
        if p:
            self.app_path.set(p)
            app_ver, target = _read_versions_from_binary(p)
            file_crc, file_size = _read_file_crc_size(p)
            if app_ver:
                tgt_txt = f", target: {target}" if target else ""
                crc_txt = f", crc: 0x{file_crc:08X}" if isinstance(file_crc, int) else ""
                size_txt = f", size: {file_size}" if isinstance(file_size, int) and file_size > 0 else ""
                self.app_ver_lbl.config(text=f"(ver: {app_ver[0]}.{app_ver[1]}.{app_ver[2]}.{app_ver[3]}{tgt_txt}{crc_txt}{size_txt})")

    def _pick_en(self):
        p = filedialog.askopenfilename()
        if p:
            self.en_path.set(p)
            en_ver, target = _read_versions_from_binary(p)
            file_crc, file_size = _read_file_crc_size(p)
            if en_ver:
                tgt_txt = f", target: {target}" if target else ""
                crc_txt = f", crc: 0x{file_crc:08X}" if isinstance(file_crc, int) else ""
                size_txt = f", size: {file_size}" if isinstance(file_size, int) and file_size > 0 else ""
                self.en_ver_lbl.config(text=f"(ver: {en_ver[0]}.{en_ver[1]}.{en_ver[2]}.{en_ver[3]}{tgt_txt}{crc_txt}{size_txt})")

    def _append(self, s: str):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, s)
        self.log_text.config(state='disabled')
        self.log_text.see(tk.END)

    def _on_engine(self, ip, addr, parsed, mac, ts, values):
        # Treat any valid boot announce as a reset for that IP: abort and clear queues
        try:
            now = time.monotonic()
            last = self._last_reset_at.get(ip, 0.0)
            self._last_reset_at[ip] = now
            # Abort any in-flight transfer to this IP
            ev = self._ip_abort.get(ip)
            if ev:
                ev.set()
            # Clear pending/active jobs for this IP (do NOT clear verify marker here)
            with self._jobs_lock:
                try:
                    from collections import deque
                    self._pending = deque(j for j in self._pending if j[0] != ip)
                except Exception:
                    pass
                try:
                    self._active.discard(ip)
                except Exception:
                    pass
        except Exception:
            pass
        # Cache last parsed for Retry and future comparisons
        try:
            if not hasattr(self, '_last_parsed'):
                self._last_parsed = {}
            if parsed:
                self._last_parsed[ip] = parsed
        except Exception:
            pass
        # Update grid tile + last device panel, and auto-enqueue updates
        try:
            # tile
            tile = self.tiles.get(ip)
            if tile is None:
                tile = self._create_tile(ip)
                self.tiles[ip] = tile
            if parsed:
                bl = parsed['bootloader']; app = parsed['app']; en = parsed['enactor']
                tile['bl'].config(text=f"BL {bl[0]}.{bl[1]}")
                ac = parsed.get('app_crc'); ec = parsed.get('enactor_crc')
                app_txt = f"App {app[0]}.{app[1]}.{app[2]}.{app[3]}" + (f" (CRC 0x{ac:08X})" if isinstance(ac, int) else "")
                en_txt = f"En {en[0]}.{en[1]}.{en[2]}.{en[3]}" + (f" (CRC 0x{ec:08X})" if isinstance(ec, int) else "")
                tile['app'].config(text=app_txt)
                tile['en'].config(text=en_txt)
                tile['last'].config(text=f"Last {ts}")
                # Verification check
                # If engine flagged empty app, show a clear status so users know why an update is triggered
                try:
                    if isinstance(parsed, dict) and (parsed.get("empty_app") or parsed.get("empty_payload")):
                        self._set_tile(ip, "Empty App Detected", "#EF6C00", 0)
                except Exception:
                    pass
                pending = self._await_verify.get(ip)
                if pending:
                    # Pending tuple may be (kind, expected, mode) where mode in {'crc','ver'}
                    try:
                        if len(pending) == 3:
                            kind, expected, mode = pending
                        else:
                            kind, expected = pending
                            mode = 'ver'
                    except Exception:
                        kind, expected, mode = 'app', None, 'ver'
                    matched = False
                    if mode == 'crc':
                        cur = parsed.get('app_crc') if kind == 'app' else parsed.get('enactor_crc')
                        if cur is not None and expected is not None and int(cur) == int(expected):
                            matched = True
                    else:
                        current = app if kind == 'app' else en
                        if expected is not None and tuple(current) == tuple(expected):
                            matched = True
                    if matched:
                        self._set_tile(ip, "Verified ✓", "#2E7D32", 100)
                        # Clear verify marker now that we've matched
                        try:
                            del self._await_verify[ip]
                        except Exception:
                            pass
                        # If we just verified the controller (app), immediately evaluate enactor
                        # and queue it if mismatched and staged. This avoids requiring another reboot.
                        if kind == 'app' and self.auto_var.get():
                            try:
                                self._maybe_enqueue(ip, parsed)
                            except Exception:
                                pass
                    else:
                        # Waiting for reboot/announce; don't re-enqueue while awaiting verify
                        pass
                else:
                    # maybe schedule update
                    if self.auto_var.get():
                        self._maybe_enqueue(ip, parsed)
            # last device panel (informational)
            self.dev_ip.config(text=f"IP: {ip}")
            if parsed:
                self.dev_bl.config(text=f"Bootloader: {bl[0]}.{bl[1]}")
                ac = parsed.get('app_crc'); ec = parsed.get('enactor_crc')
                self.dev_app.config(text=(
                    f"App: {app[0]}.{app[1]}.{app[2]}.{app[3]}" + (f"  (CRC 0x{ac:08X})" if isinstance(ac, int) else "")
                ))
                self.dev_en.config(text=(
                    f"Enactor: {en[0]}.{en[1]}.{en[2]}.{en[3]}" + (f"  (CRC 0x{ec:08X})" if isinstance(ec, int) else "")
                ))
                self.status_var.set(f"Last seen {ts}")
        except Exception:
            pass

    def _create_tile(self, ip: str) -> dict:
        f = ttk.Frame(self._tiles_host, padding=(8,6))
        # simple grid layout per tile
        title = ttk.Label(f, text=ip, style="Bold.TLabel")
        title.grid(row=0, column=0, sticky="w")
        bl = ttk.Label(f, text="BL -")
        app = ttk.Label(f, text="App -")
        en = ttk.Label(f, text="En -")
        bl.grid(row=1, column=0, sticky="w", padx=(0,8))
        app.grid(row=1, column=1, sticky="w", padx=(0,8))
        en.grid(row=1, column=2, sticky="w", padx=(0,8))
        status = ttk.Label(f, text="Up-to-date", foreground="#2E7D32")
        status.grid(row=0, column=1, sticky="w", padx=(8,0))
        p = ttk.Progressbar(f, mode="determinate", length= max(200, min(500, int((self.root.winfo_screenwidth() or 1280) * 0.22))), style="Success.Horizontal.TProgressbar")
        p.grid(row=2, column=0, columnspan=3, sticky="we", pady=(4,0))
        retry = ttk.Button(f, text="Retry", command=lambda ip=ip: self._retry(ip))
        retry.grid(row=2, column=3, padx=(8,0))
        try:
            retry.state(["disabled"])
        except Exception:
            pass
        last = ttk.Label(f, text="Last -")
        last.grid(row=0, column=2, sticky="e")
        # place tile
        r = len(self.tiles)
        f.grid(row=r, column=0, sticky="we", pady=2)
        return {"frame": f, "title": title, "bl": bl, "app": app, "en": en, "status": status, "prog": p, "last": last, "retry": retry}

    def _set_tile(self, ip: str, text: str, color: str | None = None, pct: int | None = None):
        t = self.tiles.get(ip)
        if not t:
            return
        try:
            t['status'].config(text=text, foreground=color or t['status'].cget('foreground'))
        except Exception:
            pass
        if pct is not None:
            try:
                t['prog']['value'] = max(0, min(100, int(pct)))
            except Exception:
                pass

        # Toggle Retry button availability on failure states
        try:
            if text.lower().startswith("failed") or "timed out" in text.lower():
                t['retry'].state(["!disabled"])  # enable
            else:
                t['retry'].state(["disabled"])   # disable
        except Exception:
            pass

    def _retry(self, ip: str):
        # Re-enqueue update for this device based on last known versions
        parsed = getattr(self, '_last_parsed', {}).get(ip)
        if not parsed:
            return
        tile = self.tiles.get(ip)
        if tile:
            try:
                tile['retry'].state(["disabled"])  # disable during retry
            except Exception:
                pass
        try:
            if ip in getattr(self, '_await_verify', {}):
                del self._await_verify[ip]
        except Exception:
            pass
        self._maybe_enqueue(ip, parsed)

    def _maybe_enqueue(self, ip: str, parsed: dict):
        # Decide job for this IP by staged files; prefer CRC-based mismatch, fallback to versions. App first.
        app_file = (self.app_path.get() or '').strip()
        en_file = (self.en_path.get() or '').strip()
        job = None
        # App (priority)
        if app_file and os.path.exists(app_file):
            app_crc_dev = parsed.get('app_crc')
            do_send_app = False
            file_crc, _ = _read_file_crc_size(app_file)
            # Priority rules:
            # 1) If device controller CRC missing -> update controller
            # 2) If device controller CRC present and differs from file CRC -> update controller
            if app_crc_dev is None:
                do_send_app = True
            else:
                if file_crc is not None and file_crc != app_crc_dev:
                    do_send_app = True
            if do_send_app:
                app_ver, _ = _read_versions_from_binary(app_file)
                job = (ip, 'app', app_file, app_ver)
        # Enactor (only after controller deemed same)
        if not job and en_file and os.path.exists(en_file):
            en_crc_dev = parsed.get('enactor_crc')
            do_send_en = False
            if en_crc_dev is not None:
                file_crc, _ = _read_file_crc_size(en_file)
                if file_crc is not None and file_crc != en_crc_dev:
                    do_send_en = True
            if do_send_en:
                en_ver, _ = _read_versions_from_binary(en_file)
                job = (ip, 'enactor', en_file, en_ver)
        if not job:
            # mark up-to-date visual
            self._set_tile(ip, "Up-to-date", "#2E7D32", 100)
            return
        # If we're within the boot window and not currently sending, start immediately
        try:
            if getattr(self, '_in_boot_window', None) and self._in_boot_window(ip) and not self.sending:
                kind = job[1]; path = job[2]; ver = job[3]
                self._set_tile(ip, f"Updating {kind}…", "#1565C0", 0)
                threading.Thread(target=self._send_sequence, args=(ip, [(kind, path, ver)]), daemon=True).start()
                return
        except Exception:
            pass
        # enqueue if not already pending/active (simple FIFO)
        with self._jobs_lock:
            if ip in self._active:
                return
            # avoid dupes
            for j in list(self._pending):
                if j[0] == ip:
                    return
            self._pending.append(job)
        # Visual queued hint
        try:
            self._set_tile(ip, f"Queued {job[1]}…", "#EF6C00", 0)
        except Exception:
            pass
        # If pump exists (developer-era concurrency), call it; otherwise immediate sender will consume later
        try:
            self._pump_jobs()
        except Exception:
            pass

    def _pump_jobs(self):
        with self._jobs_lock:
            while len(self._active) < int(self.max_concurrency_var.get() or 1) and self._pending:
                ip, kind, path, ver = self._pending.popleft()
                if ip in self._active:
                    continue
                self._active.add(ip)
                self._set_tile(ip, f"Updating {kind}…", "#1565C0", 0)
                threading.Thread(target=self._run_job, args=(ip, kind, path, ver), daemon=True).start()

    def _run_job(self, ip: str, kind: str, path: str, ver):
        try:
            with open(path, 'rb') as f:
                data = f.read()
            total = len(data)
            ev = threading.Event()
            try:
                self._ip_abort[ip] = ev
            except Exception:
                pass
            def prog(done, tot):
                pct = 0 if tot == 0 else int((done*100)//tot)
                self._set_tile(ip, f"Updating {kind}…", "#1565C0", pct)
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
                self._set_tile(ip, "Failed", "#C62828")
                return
            if kind == 'enactor':
                # listen for ST_PROGRESS to apply
                self._set_tile(ip, "Applying enactor…", "#6A1B9A", 0)
                done_event = threading.Event()
                last_seen = time.monotonic()
                def on_prog(ip2: str, cur: int, tot: int):
                    nonlocal last_seen
                    if ip2 != ip:
                        return
                    last_seen = time.monotonic()
                    pct = 100 if tot <= 0 else int(min(100, (cur * 100) // max(1, tot)))
                    self._set_tile(ip, "Applying enactor…", "#6A1B9A", pct)
                    if tot > 0 and cur >= tot:
                        done_event.set()
                try:
                    self.engine.add_progress_listener(on_prog)
                except Exception:
                    pass
                # best-effort local UDP helper
                try:
                    from haven_tftp.core.udp.terminal import UDPTerminal
                    from haven_tftp.constants import UDP_DEFAULT_PORT
                    helper = UDPTerminal(queue.Queue(), on_datagram=lambda d,a: self.engine.process_datagram(d,a))
                    try:
                        helper.open(UDP_DEFAULT_PORT)
                    except Exception:
                        helper = None
                except Exception:
                    helper = None
                try:
                    timeout_s = 60
                    while not done_event.wait(0.2):
                        if time.monotonic() - last_seen > timeout_s:
                            break
                    if done_event.is_set():
                        self._set_tile(ip, "Waiting reboot…", "#455A64", 100)
                        try:
                            file_crc, _ = _read_file_crc_size(path)
                            if file_crc is not None:
                                self._await_verify[ip] = ('enactor', file_crc, 'crc')
                        except Exception:
                            pass
                    else:
                        self._set_tile(ip, "Applying timed out", "#EF6C00")
                finally:
                    try:
                        self.engine.remove_progress_listener(on_prog)
                    except Exception:
                        pass
                    try:
                        if helper:
                            helper.close()
                    except Exception:
                        pass
            else:
                # app updated, wait for next boot to verify
                self._set_tile(ip, "Waiting reboot…", "#455A64", 100)
                try:
                    file_crc, _ = _read_file_crc_size(path)
                    if file_crc is not None:
                        self._await_verify[ip] = ('app', file_crc, 'crc')
                except Exception:
                    pass
            self._pump_jobs()

        finally:
            with self._jobs_lock:
                self._active.discard(ip)
            # try schedule next
            self._pump_jobs()

    def _init_styles(self):
        self.style = ttk.Style(self.root)
        # Detect main theme choice to adapt colors
        is_dark = False
        try:
            is_dark = self.style.theme_use() == "clam"
        except Exception:
            pass
        # Brand palette values stored on self for later theme toggles
        self._accent = "#2F80ED"   # bright blue
        self._accent_ok = "#27AE60"  # green
        self.apply_palette(is_dark)

    def apply_palette(self, is_dark: bool):
        # Compute palette by mode and re-style
        header_bg = "#1F3A5F" if not is_dark else "#16243A"
        header_fg = "#ffffff"
        card_bg = "#F3F6FB" if not is_dark else "#1B1F24"
        label_fg = "#444444" if not is_dark else "#E6E8EB"

        self.style.configure("SimpleHeader.TFrame", background=header_bg)
        self.style.configure("SimpleHeader.TLabel", background=header_bg, foreground=header_fg, font=("Segoe UI", 16, "bold"))
        self.style.configure("HeaderStatus.TLabel", background=header_bg, foreground=header_fg, font=("Segoe UI", 10))
        self.style.configure("Accent.TLabel", foreground=self._accent)
        self.style.configure("Bold.TLabel", font=("Segoe UI", 10, "bold"), foreground=label_fg)
        self.style.configure("Card.TLabelframe", background=card_bg)
        self.style.configure("Card.TLabelframe.Label", background=card_bg, foreground=label_fg)
        # Progress bar tint
        self.style.configure("Success.Horizontal.TProgressbar", troughcolor=card_bg)
        try:
            self.style.configure("Success.Horizontal.TProgressbar", background=self._accent_ok)
        except Exception:
            pass
        # Update browse buttons to remain visible across themes
        self._apply_button_colors(is_dark)

    def _apply_button_colors(self, is_dark: bool):
        try:
            fg = "#ffffff"
            bg = self._accent
            active_bg = "#1366D6"
            disabled_bg = "#8AAEE0"
            for b in (self.app_browse_btn, self.en_browse_btn):
                b.configure(bg=bg, fg=fg, activebackground=active_bg, activeforeground=fg, disabledforeground="#cccccc")
                # On dark card background, add a border for separation
                b.configure(relief=tk.FLAT, bd=1, highlightthickness=0)
        except Exception:
            pass

    def _update_header_status(self):
        self.header_status.config(text=f"Auto Update: {'ON' if self.auto_var.get() else 'OFF'}")

    def _maybe_auto_update(self, ip: str, parsed: dict):
        if not self.auto_var.get() or self.sending:
            return
        # Prefer CRC-based comparison if device reported CRC/size; fallback to version compare.
        app_file = self.app_path.get().strip()
        en_file = self.en_path.get().strip()
        to_send = []
        app_crc_dev = parsed.get('app_crc')
        en_crc_dev = parsed.get('enactor_crc')

        # App first (priority): if device app CRC missing OR mismatched -> update controller
        if app_file and os.path.exists(app_file):
            do_send_app = False
            file_crc, _ = _read_file_crc_size(app_file)
            if app_crc_dev is None:
                do_send_app = True
            else:
                if file_crc is not None and file_crc != app_crc_dev:
                    do_send_app = True
            if do_send_app:
                app_ver, _ = _read_versions_from_binary(app_file)
                to_send = [('app', app_file, app_ver)]

        # If no app update queued, consider enactor (only if device reports CRC and it's mismatched)
        if not to_send and en_file and os.path.exists(en_file):
            do_send_en = False
            if en_crc_dev is not None:
                file_crc, _ = _read_file_crc_size(en_file)
                if file_crc is not None and file_crc != en_crc_dev:
                    do_send_en = True
            if do_send_en:
                en_ver, _ = _read_versions_from_binary(en_file)
                to_send = [('enactor', en_file, en_ver)]
        if not to_send:
            return
        # Start send in thread (sequentially)
        self.sending = True
        self.progress['value'] = 0
        threading.Thread(target=self._send_sequence, args=(ip, to_send), daemon=True).start()

    def _send_sequence(self, ip: str, items):
        try:
            for kind, path, ver in items:
                self._append(
                    f"Updating {kind} to {ver[0]}.{ver[1]}.{ver[2]}.{ver[3]} from file: {os.path.basename(path)}\n"
                )
                with open(path, 'rb') as f:
                    data = f.read()
                total = len(data)
                # Per-IP abort for this batch
                ev = threading.Event()
                try:
                    self._ip_abort[ip] = ev
                except Exception:
                    pass
                def prog(done, tot):
                    try:
                        pct = 0 if tot == 0 else int((done * 100) // tot)
                        self._prog_q.put(pct)
                    except Exception:
                        pass
                ok = tftp_client.send_normal(
                    ip,
                    "app.bin",
                    data,
                    total,
                    lambda s: self._append(s),
                    lambda: ev.is_set(),
                    include_hex=False,
                    progress_cb=prog,
                )
                if not ok:
                    self._append("Update failed or aborted.\n")
                    break
                if kind == 'enactor':
                    # After TFTP send, track enactor application progress via UDP ASCII broadcasts
                    self._append("TFTP done. Waiting for enactor to apply update...\n")
                    try:
                        self.progress['value'] = 0
                    except Exception:
                        pass
                    done_event = threading.Event()
                    last_seen = time.monotonic()
                    def on_prog(ip2: str, cur: int, tot: int):
                        nonlocal last_seen
                        if ip2 != ip:
                            return
                        last_seen = time.monotonic()
                        pct = 100 if tot <= 0 else int(min(100, (cur * 100) // max(1, tot)))
                        try:
                            self._prog_q.put(pct)
                        except Exception:
                            pass
                        # Log a concise progress line
                        try:
                            self._append(f"Enactor progress: {cur}/{tot} ({pct}%)\n")
                        except Exception:
                            pass
                        if tot > 0 and cur >= tot:
                            done_event.set()
                    # Subscribe and wait with inactivity timeout
                    try:
                        self.engine.add_progress_listener(on_prog)
                    except Exception:
                        pass
                    # Ensure a UDP listener is active in this process (fallback if background one failed)
                    try:
                        from haven_tftp.core.udp.terminal import UDPTerminal
                        from haven_tftp.constants import UDP_DEFAULT_PORT
                        class _NullQ:
                            def put(self, _):
                                pass
                        if not getattr(self, '_local_udp', None):
                            self._local_udp = UDPTerminal(_NullQ(), on_datagram=lambda d,a: self.engine.process_datagram(d,a))
                            try:
                                self._local_udp.open(UDP_DEFAULT_PORT)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        timeout_s = 60
                        while not done_event.wait(0.2):
                            if time.monotonic() - last_seen > timeout_s:
                                break
                        if done_event.is_set():
                            try:
                                self._prog_q.put(100)
                            except Exception:
                                pass
                            self._append("Enactor apply completed.\n")
                            # mark for CRC-based verification on next boot announce
                            try:
                                file_crc, _ = _read_file_crc_size(path)
                                if file_crc is not None:
                                    self._await_verify[ip] = ('enactor', file_crc, 'crc')
                            except Exception:
                                pass
                        else:
                            self._append("Enactor apply progress timed out.\n")
                    finally:
                        try:
                            self.engine.remove_progress_listener(on_prog)
                        except Exception:
                            pass
                        try:
                            if getattr(self, '_local_udp', None):
                                self._local_udp.close()
                                self._local_udp = None
                        except Exception:
                            pass
                else:
                    # App sent; mark for CRC-based verification on next announce
                    try:
                        file_crc, _ = _read_file_crc_size(path)
                        if file_crc is not None:
                            self._await_verify[ip] = ('app', file_crc, 'crc')
                    except Exception:
                        pass
                    self._append("Done.\n")
        finally:
            self.sending = False
            try:
                self.progress['value'] = 0
            except Exception:
                pass

    def _poll_progress(self):
        # Drain queue and update progress in UI thread
        try:
            last = None
            while True:
                last = self._prog_q.get_nowait()
        except queue.Empty:
            pass
        if last is not None:
            try:
                self.progress['value'] = max(0, min(100, last))
            except Exception:
                pass
        # schedule next poll
        try:
            self.root.after(100, self._poll_progress)
        except Exception:
            pass
















