"""TFTP client strategies and helpers.

This module implements a small TFTP client capable of normal transfers and several
stress/failure simulation modes. It uses non-blocking sockets and small helper functions
to send the WRQ and wait for ACKs, and exposes high-level functions for each scenario.

General flow for a send:
1) Send WRQ (with 'octet' mode and an optional 'size' option for total bytes)
2) Receive OACK or ACK(0)
3) Send DATA blocks (512B each) with incrementing block numbers, waiting for ACK per block
4) For special modes, alter the order, duplicate, or truncate data as requested

Every public 'send_*' function follows this pattern and accepts:
- log: callable(str) for GUI logging
- aborted: callable() to allow responsive cancellation
- progress_cb: optional (done_bytes, total_bytes)
"""

import socket
import struct
import time
import random
import binascii


def _send_wrq(sock, addr, filename_req: str, total_bytes: int, log, aborted=None):
    """Send a TFTP WRQ packet and wait for OACK/ACK.

    Returns
    -------
    tuple | (None, None)
        (data, server_addr) on success, (None, None) if aborted while waiting.
    """
    opcode = 2
    mode = b"octet"
    wrq = (
        struct.pack("!H", opcode)
        + filename_req.encode()
        + b"\0"
        + mode
        + b"\0size\0"
        + str(total_bytes).encode()
        + b"\0"
    )
    sock.sendto(wrq, addr)
    log(f"Sent WRQ with size {total_bytes}\n")

    start = time.monotonic()
    timeout_s = 1.0
    while True:
        if aborted and aborted():
            return None, None
        try:
            data, srv_addr = sock.recvfrom(1024)
            return data, srv_addr
        except BlockingIOError:
            time.sleep(0.01)
        if time.monotonic() - start > timeout_s:
            log("WRQ response timeout (1s)\n")
            return None, None


def _wait_ack(sock, expect_block: int, aborted=None):
    """Wait up to 1s for ACK(expect_block); return None on timeout/abort."""
    start = time.monotonic()
    timeout_s = 1.0
    while True:
        if aborted and aborted():
            return None
        try:
            ack, _ = sock.recvfrom(1024)
            return (
                ack
                if len(ack) >= 4
                and struct.unpack("!H", ack[:2])[0] == 4
                and struct.unpack("!H", ack[2:4])[0] == expect_block
                else None
            )
        except BlockingIOError:
            time.sleep(0.01)
        if time.monotonic() - start > timeout_s:
            return None


def send_normal(
    ip: str,
    filename_req: str,
    file_data: bytes,
    total_bytes: int,
    log,
    aborted,
    include_hex: bool = True,
    progress_cb=None,
):
    """Send a file using standard TFTP semantics (ACK per 512B block).

    This is the baseline implementation used by the Simple and Developer modes.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        if not data or not addr:
            log("Failed to start transfer (no OACK/ACK).\n")
            return False
        _ = data
        pos = 0
        block_num = 1
        # Loop until all bytes are sent or an abort is requested
        while pos < len(file_data) and not aborted():
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            sock.sendto(struct.pack("!HH", 3, block_num) + block, addr)
            if include_hex:
                hex_data = binascii.hexlify(block).decode()
                if len(hex_data) > 200:
                    hex_data = hex_data[:200] + "..."
                log(f"Sent block {block_num} ({len(block)} bytes): {hex_data}\n")
            else:
                log(f"Sent block {block_num} ({len(block)} bytes)\n")
            ack = _wait_ack(sock, block_num, aborted)
            if ack is None:
                if aborted and aborted():
                    break
                log("ACK timeout or mismatch; stopping.\n")
                return False
            pos += 512
            block_num += 1
            if progress_cb:
                try:
                    progress_cb(min(pos, total_bytes), total_bytes)
                except Exception:
                    pass
        if aborted():
            log(f"Upload aborted: {pos} bytes sent\n")
            return False
        log(f"Upload complete: {total_bytes} bytes\n")
        if progress_cb:
            try:
                progress_cb(total_bytes, total_bytes)
            except Exception:
                pass
        return True
    finally:
        sock.close()


def send_out_of_order(ip, filename_req, file_data, total_bytes, log, aborted=None):
    """Send blocks with occasional 3/4 swap to simulate out-of-order delivery."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        if not data or not addr:
            log("Failed to start transfer (no OACK/ACK).\n")
            return False
        _ = data
        blocks = []
        pos = 0
        block_num = 1
        while pos < len(file_data):
            block_end = min(pos + 512, len(file_data))
            blocks.append((block_num, file_data[pos:block_end]))
            pos += 512
            block_num += 1
        idx = 0
        while idx < len(blocks) and not (aborted and aborted()):
            if idx < len(blocks) - 1 and (idx + 1) % 4 == 3:
                order = [idx + 1, idx]
            else:
                order = [idx]
            for j in order:
                bnum, block = blocks[j]
                sock.sendto(struct.pack("!HH", 3, bnum) + block, addr)
                log(f"Sent block {bnum}{' OUT OF ORDER' if len(order)==2 else ''} ({len(block)} bytes)\n")
                _wait_ack(sock, bnum, aborted)
            idx += 2 if len(order) == 2 else 1
        log("Out-of-order upload complete\n")
    finally:
        sock.close()


def send_duplicates(ip, filename_req, file_data, total_bytes, log, aborted=None):
    """Send every 5th block twice to exercise duplicate handling."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        _ = data
        pos = 0
        block_num = 1
        while pos < len(file_data) and not (aborted and aborted()):
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            pkt = struct.pack("!HH", 3, block_num) + block
            sock.sendto(pkt, addr)
            log(f"Sent block {block_num} ({len(block)} bytes)\n")
            if block_num % 5 == 0:
                time.sleep(0.05)
                sock.sendto(pkt, addr)
                log(f"Sent DUPLICATE block {block_num}\n")
            if _wait_ack(sock, block_num, aborted) is None:
                if aborted and aborted():
                    break
                log("ACK timeout or mismatch; stopping.\n")
                return False
            pos += 512
            block_num += 1
        log("Duplicate blocks upload complete\n")
    finally:
        sock.close()


def send_wrong_block_numbers(ip, filename_req, file_data, total_bytes, log, aborted=None):
    """Periodically send a wrong block number to trigger receiver error paths."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        if not data or not addr:
            log("Failed to start transfer (no OACK/ACK).\n")
            return False
        _ = data
        pos = 0
        block_num = 1
        while pos < len(file_data) and not (aborted and aborted()):
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            wrong_num = block_num + 10 if block_num % 7 == 0 else block_num
            sock.sendto(struct.pack("!HH", 3, wrong_num) + block, addr)
            if wrong_num != block_num:
                log(f"Sent block with WRONG NUMBER {wrong_num} (should be {block_num})\n")
            else:
                log(f"Sent block {block_num} ({len(block)} bytes)\n")
            try:
                sock.settimeout(1.0)
                _ = sock.recvfrom(1024)
                sock.settimeout(None)
            except Exception:
                sock.settimeout(None)
                if aborted and aborted():
                    break
                log(f"No ACK received for block {block_num}\n")
            pos += 512
            block_num += 1
        log("Wrong block numbers upload complete\n")
    finally:
        sock.close()


def send_truncated(ip, filename_req, file_data, total_bytes, log, aborted=None):
    """Stop at ~60% of the file to simulate premature end-of-transfer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        if not data or not addr:
            log("Failed to start transfer (no OACK/ACK).\n")
            return False
        _ = data
        truncate_at = int(len(file_data) * 0.6)
        pos = 0
        block_num = 1
        while pos < truncate_at and not (aborted and aborted()):
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            sock.sendto(struct.pack("!HH", 3, block_num) + block, addr)
            log(f"Sent block {block_num} ({len(block)} bytes)\n")
            _wait_ack(sock, block_num, aborted)
            pos += 512
            block_num += 1
        log(f"Transfer TRUNCATED at {pos} bytes (60% of {total_bytes})\n")
    finally:
        sock.close()


def send_timeout_pause(ip, filename_req, file_data, total_bytes, log, aborted=None):
    """Pause for 10 seconds at a specific block to simulate timeouts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        if not data or not addr:
            log("Failed to start transfer (no OACK/ACK).\n")
            return False
        _ = data
        pause_at_block = 5
        pos = 0
        block_num = 1
        while pos < len(file_data) and not (aborted and aborted()):
            if block_num == pause_at_block:
                log("PAUSING for 10 seconds to simulate timeout\n")
                time.sleep(10)
                log("Resuming transfer...\n")
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            sock.sendto(struct.pack("!HH", 3, block_num) + block, addr)
            log(f"Sent block {block_num} ({len(block)} bytes)\n")
            _wait_ack(sock, block_num, aborted)
            pos += 512
            block_num += 1
        log("Timeout simulation upload complete\n")
    finally:
        sock.close()


def send_packet_loss(ip, filename_req, file_data, total_bytes, log, aborted=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        data, addr = _send_wrq(sock, (ip, 69), filename_req, total_bytes, log, aborted)
        _ = data
        pos = 0
        block_num = 1
        dropped_count = 0
        while pos < len(file_data) and not (aborted and aborted()):
            block_end = min(pos + 512, len(file_data))
            block = file_data[pos:block_end]
            if random.random() < 0.3:
                dropped_count += 1
                log(f"DROPPED packet for block {block_num}\n")
            else:
                sock.sendto(struct.pack("!HH", 3, block_num) + block, addr)
                log(f"Sent block {block_num} ({len(block)} bytes)\n")
                _wait_ack(sock, block_num, aborted)
            pos += 512
            block_num += 1
        log(f"Packet loss simulation complete - dropped {dropped_count} packets\n")
    finally:
        sock.close()
