"""Small pop-up dialogs used across the GUI.

Currently contains:
- UDPWritePopup: simple dialog to send a UDP datagram to an IP:port
"""

import tkinter as tk
from tkinter import messagebox, ttk
import socket
from haven_tftp.constants import UDP_DEFAULT_PORT, DEFAULT_TARGET_IP


class UDPWritePopup:
    def __init__(self, parent):
        self.parent = parent
        self.popup = tk.Toplevel(parent.root)
        self.popup.title("UDP Write")
        self.popup.geometry("360x240")

        ttk.Label(self.popup, text="Target IP:").pack(pady=5)
        self.target_ip = ttk.Entry(self.popup)
        self.target_ip.pack(pady=5)
        self.target_ip.insert(0, DEFAULT_TARGET_IP)

        ttk.Label(self.popup, text="Target Port:").pack(pady=5)
        self.target_port = ttk.Entry(self.popup)
        self.target_port.pack(pady=5)
        self.target_port.insert(0, str(UDP_DEFAULT_PORT))

        ttk.Label(self.popup, text="Message:").pack(pady=5)
        self.message_entry = tk.Text(
            self.popup,
            height=5,
            font=("Consolas", 10),
        )
        self.message_entry.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(self.popup)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Send", command=self.send_udp).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.popup.destroy).pack(side=tk.LEFT, padx=5)

    def send_udp(self):
        ip = self.target_ip.get()
        try:
            port = int(self.target_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return
        message = self.message_entry.get("1.0", tk.END).strip().encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, (ip, port))
            sock.close()
        except Exception as e:
            messagebox.showerror("Error", str(e))
