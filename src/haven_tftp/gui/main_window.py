"""Main application window and theme management.

Responsibilities:
- Initialize the application shell and status bar
- Spawn the appropriate mode (Developer vs Simple)
- Manage a background UDP listener in Simple mode to feed the boot engine
- Provide a central place to tweak ttk themes for Light/Dark modes
"""
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont
from datetime import datetime

from haven_tftp.gui.tftp_panel import TFTPPanel
from haven_tftp.gui.udp_panel import UDPPanel
from haven_tftp.gui.boot_monitor import BootAnnounceWindow, BootAnnounceEngine
from haven_tftp.gui.simple_panel import SimpleUpdatePanel


class MainWindow:
    def __init__(self, root: tk.Tk, mode: str = "simple"):
        self.root = root
        self.mode = mode
        self._build()

    def _build(self):
        # Theme and fonts
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except Exception:
            try:
                style.theme_use("clam")
            except Exception:
                pass
        default_font = tkfont.nametofont("TkDefaultFont")
        # Slightly larger default font for better readability
        default_font.configure(family="Segoe UI", size=11)
        heading_font = tkfont.nametofont("TkHeadingFont") if "TkHeadingFont" in tkfont.names() else default_font
        try:
            heading_font.configure(family="Segoe UI", size=11, weight="bold")
        except Exception:
            pass

        container = ttk.Frame(self.root)
        container.pack(fill="both", expand=True)

        # Status bar
        try:
            from haven_tftp.constants import APP_VERSION, APP_NAME
            init_status = f"{APP_NAME} v{APP_VERSION} — Ready"
        except Exception:
            init_status = "Ready"
        self.status_text = tk.StringVar(value=init_status)
        status = ttk.Label(self.root, textvariable=self.status_text, anchor="w")
        status.pack(side=tk.BOTTOM, fill=tk.X)

        def set_status(msg: str):
            try:
                self.status_text.set(msg)
            except Exception:
                pass

        # Top bar with theme selector
        topbar = ttk.Frame(container)
        topbar.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(topbar, text="Theme:").pack(side=tk.LEFT, padx=(4, 4), pady=4)
        self.theme_var = tk.StringVar(value="Light")
        theme_box = ttk.Combobox(topbar, textvariable=self.theme_var, values=["Light", "Dark"], state="readonly", width=10)
        theme_box.pack(side=tk.LEFT, padx=(0, 8), pady=4)
        theme_box.bind("<<ComboboxSelected>>", lambda e: self._apply_theme(self.theme_var.get()))

        ttk.Button(topbar, text="Boot Monitor", command=self._open_boot_monitor).pack(side=tk.LEFT, padx=4, pady=4)

        # Side-by-side panels (no tabs)
        paned = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True)
        left_pane = ttk.Frame(paned, padding=4)
        right_pane = ttk.Frame(paned, padding=4)
        paned.add(left_pane, weight=1)
        paned.add(right_pane, weight=1)

        # Background engine and panels
        self.boot_engine = BootAnnounceEngine()
        self.boot_monitor: BootAnnounceWindow | None = None
        self.tftp = None
        self.udp = None
        self.simple = None

        # Shared UDP terminal feeding the boot engine (single binder across app)
        self._shared_udp = None
        try:
            from haven_tftp.core.udp.terminal import UDPTerminal
            from haven_tftp.constants import UDP_DEFAULT_PORT
            class _NullQ:
                def put(self, _):
                    pass
            self._shared_udp = UDPTerminal(_NullQ(), on_datagram=lambda d,a: self.boot_engine.process_datagram(d,a))
            try:
                self._shared_udp.open(UDP_DEFAULT_PORT)
            except Exception:
                # Keep None if binding failed (another tool may be listening)
                self._shared_udp = None
        except Exception:
            self._shared_udp = None

        if self.mode == "developer":
            paned = ttk.Panedwindow(container, orient=tk.HORIZONTAL)
            paned.pack(fill="both", expand=True)
            left_pane = ttk.Frame(paned, padding=4)
            right_pane = ttk.Frame(paned, padding=4)
            paned.add(left_pane, weight=1)
            paned.add(right_pane, weight=1)

            self.tftp = TFTPPanel(left_pane, set_status=set_status, engine=self.boot_engine)
            self.udp = UDPPanel(right_pane, on_datagram=self._on_udp_datagram2, terminal=self._shared_udp, engine=self.boot_engine)
        else:
            # Simple Updater full screen
            self.simple = SimpleUpdatePanel(container, engine=self.boot_engine)
            # If shared listener failed, leave a concise hint; otherwise nothing to do
            if self._shared_udp is None:
                try:
                    from haven_tftp.constants import UDP_DEFAULT_PORT
                    self.simple._append(f"Note: UDP {UDP_DEFAULT_PORT} unavailable; broadcasts may not appear.\n")
                except Exception:
                    pass

        # Default theme
        self._apply_theme(self.theme_var.get())

    def _apply_theme(self, mode: str):
        style = ttk.Style(self.root)
        accent = "#2F80ED"
        dark = mode.lower() == "dark"

        # Prefer 'clam' for dark so ttk colors apply more consistently on Windows
        try:
            if dark and style.theme_use() != "clam":
                style.theme_use("clam")
            if not dark and style.theme_use() != "vista":
                style.theme_use("vista")
        except Exception:
            pass

        if dark:
            # Dark palette tuned for readability
            bg = "#121417"
            fg = "#E6E8EB"
            ctrl_bg = "#1B1F24"
            field_bg = "#20252B"

            style.configure("TFrame", background=bg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("SectionTitle.TLabel", background=bg, foreground=accent)
            style.configure("TButton", background=ctrl_bg, foreground=fg, padding=(10, 6))
            style.configure("TCheckbutton", background=bg, foreground=fg)
            style.configure("TRadiobutton", background=bg, foreground=fg)
            style.configure("TEntry", fieldbackground=field_bg, foreground=fg)
            style.configure("TCombobox", fieldbackground=field_bg, foreground=fg, background=ctrl_bg)
            style.configure("TLabelframe", background=bg)
            style.configure("TLabelframe.Label", background=bg, foreground=fg)
            style.configure("TPanedwindow", background=bg)
            style.configure("TScrollbar", background=ctrl_bg)
            # Treeview (Boot Monitor)
            style.configure("Treeview", background=ctrl_bg, fieldbackground=ctrl_bg, foreground=fg, rowheight=22)
            style.configure("Treeview.Heading", background=ctrl_bg, foreground=fg)
            text_cfg = {"bg": "#0E1013", "fg": fg, "insertbackground": fg}
        else:
            # Light/default
            style.configure("TFrame")
            style.configure("TLabel", foreground="black")
            style.configure("SectionTitle.TLabel", foreground=accent)
            style.configure("TButton", padding=(10, 6))
            style.configure("TCheckbutton")
            style.configure("TRadiobutton")
            style.configure("TEntry", fieldbackground="white", foreground="black")
            style.configure("TCombobox", fieldbackground="white", foreground="black", background="white")
            style.configure("TLabelframe")
            style.configure("TLabelframe.Label")
            style.configure("TPanedwindow")
            style.configure("TScrollbar")
            style.configure("Treeview", rowheight=22)
            text_cfg = {"bg": "white", "fg": "black", "insertbackground": "black"}

        # Apply to panels' Text widgets
        try:
            if self.tftp:
                self.tftp.apply_text_theme(text_cfg)
        except Exception:
            pass
        try:
            if self.udp:
                self.udp.apply_text_theme(text_cfg)
        except Exception:
            pass
        try:
            if self.simple:
                # Propagate to Simple Updater log text
                self.simple.apply_text_theme(text_cfg)
                # Also adjust palette colors (buttons, cards)
                self.simple.apply_palette(dark)
            
        except Exception:
            pass
        try:
            if self.boot_monitor:
                self.boot_monitor.apply_text_theme(text_cfg)
        except Exception:
            pass

    def _open_boot_monitor(self):
        try:
            if self.boot_monitor and self.boot_monitor.win.winfo_exists():
                self.boot_monitor.win.deiconify()
                self.boot_monitor.win.lift()
                return
        except Exception:
            pass
        self.boot_monitor = BootAnnounceWindow(self.root, engine=self.boot_engine)
        # Apply current theme to raw text
        mode = self.theme_var.get()
        if mode.lower() == "dark":
            cfg = {"bg": "#111111", "fg": "#e5e5e5", "insertbackground": "#e5e5e5"}
        else:
            cfg = {"bg": "white", "fg": "black", "insertbackground": "black"}
        self.boot_monitor.apply_text_theme(cfg)

    def _on_udp_datagram2(self, data: bytes, addr):
        # Always parse with background engine; add a stable marker to UDP log on success
        try:
            parsed = self.boot_engine.process_datagram(data, addr)
        except Exception:
            parsed = None
        if parsed and getattr(self, 'udp', None):
            try:
                ts = datetime.now().strftime("%H:%M:%S")
                app = parsed.get("app", (0, 0, 0, 0))
                ac = parsed.get("app_crc"); ec = parsed.get("enactor_crc")
                acs = f"  app_crc=0x{ac:08X}" if isinstance(ac, int) else ""
                ecs = f"  en_crc=0x{ec:08X}" if isinstance(ec, int) else ""
                marker = (
                    f"[{ts}] [TF] TinyFrame Boot: {addr[0]:<15}:{addr[1]:<5} "
                    f"id=0x{parsed['id']:04X} type={parsed['type']} "
                    f"app={app[0]}.{app[1]}.{app[2]}.{app[3]}{acs}{ecs}\n"
                )
                self.udp.msg_queue.put(marker)
            except Exception:
                pass

    def _on_udp_datagram(self, data: bytes, addr):
        # Always parse with background engine
        try:
            parsed = self.boot_engine.process_datagram(data, addr)
            if parsed and hasattr(self, 'udp') and self.udp:
                # Add a small indicator line in UDP log and let filters/pins catch it
                ts = datetime.now().strftime("%H:%M:%S")
                app = parsed.get("app", (0, 0, 0, 0))
                ac = parsed.get("app_crc"); ec = parsed.get("enactor_crc")
                acs = f"  app_crc=0x{ac:08X}" if isinstance(ac, int) else ""
                ecs = f"  en_crc=0x{ec:08X}" if isinstance(ec, int) else ""
                marker = (
                    f"[{ts}] [TF] TinyFrame Boot: {addr[0]:<15}:{addr[1]:<5} "
                    f"id=0x{parsed['id']:04X} type={parsed['type']} "
                    f"app={app[0]}.{app[1]}.{app[2]}.{app[3]}{acs}{ecs}\n"
                )
                try:
                    self.udp.msg_queue.put(marker)
                except Exception:
                    pass
        except Exception:
            pass

    def on_close(self):
        # Give panels a chance to clean up
        try:
            if self.tftp:
                self.tftp.on_close()
        except Exception:
            pass
        try:
            if self.udp:
                self.udp.on_close()
        except Exception:
            pass
        try:
            if getattr(self, '_shared_udp', None):
                self._shared_udp.close()
        except Exception:
            pass
        self.root.destroy()



