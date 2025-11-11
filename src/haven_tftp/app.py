"""App entry and mode selector.

This module creates the Tk root, prompts for the desired mode (Simple vs
Developer), and then constructs the MainWindow accordingly.
"""

import tkinter as tk
from tkinter import ttk
from haven_tftp.gui.main_window import MainWindow
from haven_tftp.constants import APP_NAME, APP_VERSION


def _ask_mode(root: tk.Tk) -> str:
    sel = {"mode": None}

    dlg = tk.Toplevel(root)
    dlg.title("Choose Mode")
    dlg.transient(root)
    dlg.grab_set()
    frm = ttk.Frame(dlg, padding=20)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text="Select How You Want To Use It", font=("Segoe UI", 12, "bold")).pack(pady=(0,12))
    btns = ttk.Frame(frm)
    btns.pack()
    def choose(m):
        sel["mode"] = m
        dlg.destroy()
    ttk.Button(btns, text="Simple Updater", width=22, command=lambda: choose("simple")).pack(side=tk.LEFT, padx=8, pady=6)
    ttk.Button(btns, text="Developer Mode", width=22, command=lambda: choose("developer")).pack(side=tk.LEFT, padx=8, pady=6)
    root.wait_window(dlg)
    return sel["mode"] or "simple"


def main() -> None:
    root = tk.Tk()
    # Attempt to scale UI based on screen DPI so it renders consistently
    try:
        sw = root.winfo_screenwidth()
        smm = root.winfo_screenmmwidth() or 320  # avoid div by zero
        dpi = (sw / smm) * 25.4
        scaling = max(0.8, min(2.0, dpi / 72.0))
        root.tk.call('tk', 'scaling', scaling)
    except Exception:
        pass
    root.title(f"{APP_NAME} v{APP_VERSION}")
    # Optional icon (place an ICO at assets/app.ico)
    try:
        import os
        ico = os.path.join(os.path.dirname(__file__), '..', 'assets', 'app.ico')
        ico = os.path.abspath(ico)
        if os.path.exists(ico):
            root.iconbitmap(ico)
    except Exception:
        pass
    mode = _ask_mode(root)
    app = MainWindow(root, mode=mode)
    if mode == "simple":
        try:
            root.state('zoomed')
        except Exception:
            # Fallback: size to ~90% of screen
            try:
                w = int((root.winfo_screenwidth() or 1280) * 0.9)
                h = int((root.winfo_screenheight() or 800) * 0.9)
                root.geometry(f"{w}x{h}")
            except Exception:
                pass
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
