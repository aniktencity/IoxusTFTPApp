# IOXUS BL Updater (TFTP + UDP Utility)

Graphical TFTP and UDP testing tool with builtâ€‘in failure simulation modes, a live UDP terminal, and an alwaysâ€‘on TinyFrame boot announce monitor. Designed to help validate and stress test MCU bootloader and firmware upgrade flows.

Highlights
- TFTP Send (client) with 7 failure simulations (outâ€‘ofâ€‘order, duplicates, wrong block, truncated, timeout pause, packet loss, data swap)
- TFTP Listen (server) for WRQ write requests with corruption/missing block detection
- UDP Terminal (listener + write popup) with HEX/ASCII view, filtering, pins, and save/clear
- Boot Announce Monitor (TinyFrame) with background engine, device table, CSV export, MAC learning, and filters
- Theme toggle (Light/Dark), status bar, clean ttk UI
- Windows oneâ€‘file EXE build via PyInstaller

Features
- TFTP Send (Client)
  - Normal send and 7 failure simulations:
    - Outâ€‘ofâ€‘Order (swap some packet order)
    - Duplicates (send some blocks twice)
    - Wrong Block # (offset numbering periodically)
    - Truncated (stop at 60%)
    - Timeout (pause midâ€‘transfer)
    - Packet Loss (drop ~30% of blocks)
    - Data Swap (swap two random bytes in the data)
  - Pinned success entry with file/size/time on completion
  - â€œShow HEX in logâ€ toggle to reduce verbosity

- TFTP Listen (Server)
  - Listens for WRQ (write) on port 69 and writes to chosen file
  - Detects missing blocks, outâ€‘ofâ€‘order blocks, size mismatches
  - Logs warnings (âš /ðŸš¨) for easy filtering
  - Note: Port 69 often requires admin rights/firewall rules on Windows

- UDP Terminal
  - Listens on any port (default 40000)
  - Shows received packets in both HEX and ASCII (toggle: Both/HEX/ASCII)
  - UDP Write popup to send arbitrary payloads
  - Save Log and Clear Log
  - Filtering: freeâ€‘text filter + â€œImportant onlyâ€ toggle
  - Pinned Important list (captures âš  ðŸš¨ Error DROPPED MISSING CORRUPTED TIMEOUT Size mismatch TinyFrame)
  - Injects a concise marker when a TinyFrame boot announce is recognized

- Boot Announce Monitor
  - Alwaysâ€‘on background engine parses every UDP datagram
  - TinyFrame parsing (header + payload CRC32 variants supported)
  - Device table with: IP, MAC, Type, Msg ID, Bootloader, App, Enactor, Struct Ver, Last Seen
  - Details panel with raw payload view
  - CSV Export, â€œPing to ARPâ€, â€œRefresh MACsâ€
  - Filters by Type and ID
  - MAC learning from separate ASCII messages like `IP=..., MAC=...`
  - Feeds TFTP Target IP dropdown automatically once devices are seen

Quick Start (Dev)
1. python -m venv .venv
2. .\.venv\Scripts\activate
3. pip install -U pip
4. pip install -e .
5. python .\scripts\run_dev.py

Tips
- If TFTP Listen is used, port 69 may require admin rights or a firewall rule.
- Use Light/Dark theme from the top bar.

Using The App
- TFTP
  - Target IP: dropdown autoâ€‘populated from Boot announces (or type manually)
  - Browse a file, click â€œTFTP Sendâ€ for a normal upload
  - Red buttons simulate failures for stress testing
  - Successes are pinned; logs can be filtered, saved, or cleared

- TFTP Listen
  - Switch to Listen mode; set output filename (defaults to received.bin)
  - Click Start Listen; watch for WRQ requests and data blocks
  - Corruption/missing blocks warnings appear in the log

- UDP Terminal
  - Set port (default 40000), click â€œUDP Openâ€
  - Use â€œUDP Writeâ€ to send test messages
  - Toggle display (Both/HEX/ASCII), apply filter, and save/clear logs
  - TinyFrameâ€‘recognized frames inject a oneâ€‘line marker and are considered â€œImportantâ€

- Boot Announce Monitor
  - Open â€œBoot Monitorâ€ from the top bar
  - Table fills as announces arrive (even if the window wasnâ€™t open)
  - Select a row to populate details and raw payload
  - Export CSV; â€œPing to ARPâ€ then â€œRefresh MACsâ€ to fill MACs quickly
  - Filter by Type and ID as needed

Stressâ€‘Testing Playbook
- Connectivity
  - Point MCU boot announce and TFTP traffic to the PC running this tool (UDP/TFTP)
  - Verify UDP markers and Boot table entries appear for each device

- TFTP Robustness
  - For each device, run sends with: Outâ€‘ofâ€‘Order, Duplicates, Wrong Block #, Truncated, Timeout, Packet Loss, Data Swap
  - Observe server or device behavior (retries, error handling, acceptance)
  - Verify TFTP Listen logs show expected warnings and size checks

- Bootloader Upgrade
  - Use the Boot table to pick target IPs from the TFTP dropdown
  - Run normal TFTP sends for firmware images; confirm pinned success entries
  - Repeat under adverse conditions using the failure modes

Logs & Filtering
- Filter: freeâ€‘text; Apply/Reset to reâ€‘render views from buffered logs
- Important only: narrows view to warnings/errors and TinyFrame markers
- Save Log: exports the current text view (useful for reports)
- Pinned Important: quick access to key events; Clear Pins to reset

Build a Windows .exe (PyInstaller)
- From the `haven-tftp` folder run: `scripts\build_exe.bat`
- Output: `dist\HavenTFTP.exe`
- Notes:
  - Uses a local venv (`.venv`) and installs PyInstaller automatically
  - Bundles the `assets` folder (if present) alongside the app
  - GUI app, no console window (`--noconsole`)

Troubleshooting
- TFTP Listen fails to bind port 69
  - Run as administrator or add a firewall rule, or test on a nonâ€‘privileged port with device retargeted
- No MACs shown
  - Use â€œPing to ARPâ€ then â€œRefresh MACsâ€; or send ASCII `IP=..., MAC=...` messages
- TinyFrame not recognized
  - Ensure SOF/ID/LEN/TYPE/CRC are per your build; the app accepts both standard and TinyFrame CRC32 variants
- Abort/Restart
  - Click â€œAbort Sendâ€ in Developer mode to stop a running transfer promptly.
  - The transfer restarts automatically with the same parameters (toggle can be added if you prefer manual restart).
  - Simple mode respects Auto Update toggle; aborts pause current transfer and will retry on next boot announce event.


