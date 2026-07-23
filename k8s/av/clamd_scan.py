#!/usr/bin/env python3
"""
Minimal clamd INSTREAM client. Avoids depending on the clamdscan CLI binary
entirely (which has had packaging/config-path inconsistencies across distros).
Speaks clamd's native protocol directly over a plain TCP socket.

Usage: clamd_scan.py <host> <port> <file_path>
Exit codes: 0 = clean, 1 = infected, 2 = error
Prints a single line of output mimicking clamdscan's format, e.g.:
  /path/to/file: OK
  /path/to/file: Win.Test.EICAR_HDB-1 FOUND
  /path/to/file: ERROR <message>
"""
import socket
import struct
import sys

CHUNK_SIZE = 8192

def scan_file(host: str, port: int, file_path: str, timeout: float = 30.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zINSTREAM\0")
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            # zero-length chunk signals end of stream
            sock.sendall(struct.pack("!L", 0))

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                if b"\0" in response or response.endswith(b"\n"):
                    break
            return response.decode("utf-8", errors="replace").strip().rstrip("\x00")
    except Exception as e:
        return f"ERROR {type(e).__name__}: {e}"

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"{sys.argv[0]}: ERROR usage: clamd_scan.py <host> <port> <file_path>")
        sys.exit(2)

    host, port, file_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    result = scan_file(host, port, file_path)

    if result.startswith("ERROR"):
        print(f"{file_path}: {result}")
        sys.exit(2)
    elif "FOUND" in result:
        # clamd replies like: "stream: Win.Test.EICAR_HDB-1 FOUND"
        sig = result.split(":", 1)[1].strip() if ":" in result else result
        print(f"{file_path}: {sig}")
        sys.exit(1)
    elif "OK" in result:
        print(f"{file_path}: OK")
        sys.exit(0)
    else:
        print(f"{file_path}: ERROR unexpected response: {result}")
        sys.exit(2)
