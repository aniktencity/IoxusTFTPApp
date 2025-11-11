import tkinter as tk


class ToolTip:
    """Create a tooltip for a given widget.

    Lightweight utility for short, wrapped tooltips.
    """

    def __init__(self, widget: tk.Widget, text: str):
        self.widget = widget
        self.text = text
        self.tooltip: tk.Toplevel | None = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)

    def on_enter(self, _event=None):
        try:
            bbox = self.widget.bbox("insert") or (0, 0, 0, 0)
            x, y = bbox[0], bbox[1]
        except Exception:
            x = y = 0
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            self.tooltip,
            text=self.text,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            font=("Arial", 9),
            wraplength=300,
            justify="left",
            padx=5,
            pady=3,
        )
        label.pack()

    def on_leave(self, _event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
