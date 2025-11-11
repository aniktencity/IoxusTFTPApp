import socket
import struct
import threading


class TFTPServer:
    """Minimal TFTP WRQ receiver for testing with corruption warnings.

    Writes to a specified output filename and logs to a provided queue.
    Not production-hardened; intended for local testing.
    """

    def __init__(self, ip: str, out_filename: str, msg_queue):
        self.ip = ip
        self.out_filename = out_filename
        self.msg_queue = msg_queue
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.listening = False

    def start(self):
        if self.listening:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, 69))
        self.listening = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self.msg_queue.put(f"Listening for TFTP on {self.ip}:69\n")

    def stop(self):
        self.listening = False
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.msg_queue.put("Stopped listening\n")

    def _serve(self):
        assert self.sock is not None
        sock = self.sock
        while self.listening:
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                break
            if len(data) < 2:
                continue
            opcode = struct.unpack("!H", data[:2])[0]
            if opcode != 2:  # WRQ only
                continue

            # Parse filename and mode
            try:
                filename_end = data[2:].find(b"\0")
                filename_req = data[2 : 2 + filename_end].decode()
                mode_start = 2 + filename_end + 1
                mode_end_rel = data[mode_start:].find(b"\0")
                mode_end = mode_start + mode_end_rel
                mode = data[mode_start:mode_end].decode()
            except Exception:
                self.msg_queue.put("Malformed WRQ\n")
                continue
            self.msg_queue.put(f"WRQ from {addr}: {filename_req} ({mode})\n")

            # Options
            opt_data = data[mode_end + 1 :]
            expected_size = None
            while len(opt_data) > 0:
                key_end = opt_data.find(b"\0")
                if key_end == -1:
                    break
                key = opt_data[:key_end].decode()
                opt_data = opt_data[key_end + 1 :]
                val_end = opt_data.find(b"\0")
                if val_end == -1:
                    break
                val = opt_data[:val_end].decode()
                opt_data = opt_data[val_end + 1 :]
                if key == "size":
                    try:
                        expected_size = int(val)
                    except ValueError:
                        expected_size = None

            # Send OACK if size given; else ACK 0
            if expected_size is not None:
                oack = struct.pack("!H", 6) + b"size\0" + str(expected_size).encode() + b"\0"
                sock.sendto(oack, addr)
                self.msg_queue.put(f"Sent OACK with expected size {expected_size}\n")
            else:
                ack = struct.pack("!HH", 4, 0)
                sock.sendto(ack, addr)

            # Receive file blocks
            total_received = 0
            missing_blocks: list[int] = []
            with open(self.out_filename, "wb") as f:
                block_num = 1
                while self.listening:
                    try:
                        sock.settimeout(1.0)
                        data_pkt, addr_check = sock.recvfrom(1024)
                        sock.settimeout(None)
                    except socket.timeout:
                        if expected_size is not None and total_received < expected_size:
                            missing_bytes = expected_size - total_received
                            self.msg_queue.put(
                                f"âš ï¸ TIMEOUT – expected more data. Missing approximately {missing_bytes} bytes.\n"
                            )
                            self.msg_queue.put(
                                "âš ï¸ WARNING: This file appears to be CORRUPTED – some packets were not received.\n"
                            )
                        break

                    if addr_check != addr or len(data_pkt) < 4:
                        continue
                    pkt_opcode = struct.unpack("!H", data_pkt[:2])[0]
                    if pkt_opcode != 3:  # DATA
                        break
                    block = struct.unpack("!H", data_pkt[2:4])[0]

                    if block != block_num:
                        if block > block_num:
                            for missing in range(block_num, block):
                                missing_blocks.append(missing)
                                self.msg_queue.put(
                                    f"âš ï¸ WARNING: MISSING BLOCK {missing}! Expected {block_num}, received {block}\n"
                                )
                            block_num = block
                        else:
                            self.msg_queue.put(
                                f"âš ï¸ WARNING: WARNING: Duplicate/out-of-order block {block}, expected {block_num}\n"
                            )
                            continue

                    filedata = data_pkt[4:]
                    f.write(filedata)
                    total_received += len(filedata)
                    if missing_blocks:
                        self.msg_queue.put(
                            f"Received block {block_num} ({len(filedata)} bytes) - GAPS DETECTED\n"
                        )
                    else:
                        self.msg_queue.put(
                            f"Received block {block_num}, {len(filedata)} bytes\n"
                        )

                    ack_pkt = struct.pack("!HH", 4, block_num)
                    sock.sendto(ack_pkt, addr)
                    block_num += 1
                    if len(filedata) < 512:
                        break

            # Post checks
            if missing_blocks:
                self.msg_queue.put("\nðŸš¨ FILE CORRUPTION DETECTED! ðŸš¨\n")
                self.msg_queue.put(f"WARNING: MISSING BLOCKs: {missing_blocks}\n")
                self.msg_queue.put(
                    f"Missing approximately {len(missing_blocks) * 512} bytes of data.\n"
                )
                self.msg_queue.put("âš ï¸ This file is CORRUPTED and should not be used!\n\n")

            if expected_size is not None:
                if total_received != expected_size:
                    missing_bytes = expected_size - total_received
                    self.msg_queue.put("ðŸš¨ SIZE MISMATCH DETECTED! ðŸš¨\n")
                    self.msg_queue.put(
                        f"Expected {expected_size} bytes, received {total_received} bytes\n"
                    )
                    self.msg_queue.put(
                        f"Missing {missing_bytes} bytes - FILE IS CORRUPTED!\n"
                    )
                else:
                    if missing_blocks:
                        self.msg_queue.put(
                            f"File size matches expected ({total_received} bytes) but blocks are missing - FILE IS STILL CORRUPTED!\n"
                        )
                    else:
                        self.msg_queue.put(
                            f"File received successfully: {self.out_filename} ({total_received} bytes, matches expected)\n"
                        )
            else:
                if missing_blocks:
                    self.msg_queue.put(
                        f"File received: {self.out_filename} ({total_received} bytes) - âš ï¸ BUT CORRUPTED DUE TO WARNING: MISSING BLOCKS!\n"
                    )
                else:
                    self.msg_queue.put(
                        f"File received: {self.out_filename} ({total_received} bytes)\n"
                    )


