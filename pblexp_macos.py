#!/usr/bin/env python3
"""Native macOS port of the RMX1901 pblexp/oppo710 workflow.

This is a host-side, read/serve-only tool.  It never sends Firehose XML that
writes storage and never flashes, erases, or patches a partition.  The only
Firehose traffic it sends is the benign <configure> used as an execution ping.

Subcommands:
  host            send Hello710, ELF header, program headers, segment1, zero,
                  175 x 0x13 resets, segment2 + segment3
  serve           open the loader port, send HELLO_RESP, serve a programmer
  all             host + handoff + serve in one process
  ping            send a benign Firehose <configure> and wait for <response>
  check-resources verify resource sizes/hashes (and optionally the image)
  dry-run         print the exact sequence without opening a serial port
  self-test       offline tests (no device)
  list-ports      list candidate Qualcomm 9008 serial ports

macOS uses packet-buffered libusb bulk endpoints; serial is optional elsewhere.
Use --port or --usb-bus/--usb-address to select a single device.
"""

from __future__ import annotations

import argparse
import hashlib
import errno
import math
import logging
import os
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from usb_edl import UsbEdl, find_devices as edl_find_devices, EdlInterface
except Exception as _edl_exc:  # fallback to the local pyusb transport
    usb_edl = None
    _EDL_IMPORT_ERROR = _edl_exc
else:
    usb_edl = True
    _EDL_IMPORT_ERROR = None

# ---------------------------------------------------------------------------
# Constants / resources
# ---------------------------------------------------------------------------

RESOURCE_SPECS: Dict[str, Tuple[int, str]] = {
    "oppo710_elf_header.bin": (
        0x40,
        "8b0783b70f4793cdddbce64d51775ec1b261a65968ef3087bd44aa046360ba4a",
    ),
    "oppo710_program_headers.bin": (
        0x4D0,
        "fbb4b23984616972b225c48298a9f82d8d39c76b0ca304e066c095be28ead42e",
    ),
    "segment1.bin": (
        0x1000,
        "da6cffd174d8bac3d56b7b024ff35cca6d393368f7de7a719ea3e0f2bff58b5b",
    ),
    "segment2.bin": (
        0x3F0,
        "26712a9af552ca20a9594ab0f6eb96427b302388a47f7f8672c6b002fa36aa3a",
    ),
    "segment3.bin": (
        0x3A8,
        "d68e5c4385f289c59469c0567718a4b127a56321cf3bb722298c58814d312692",
    ),
    "common_zero_segment.bin": (
        0xBF8,
        "cb9d8ad98a67bce84c7726b113d37ba7b9a48a87431c0ad9422ffbbb85da4e51",
    ),
}

ZERO_PBLEXP = 0xBF8
ZERO_PBL_REQUEST = 0xBE8
ZERO_CHOICES = (ZERO_PBLEXP, ZERO_PBL_REQUEST)
IMAGE_ID = 0x0D
MAX_IMAGE_REQUEST = 1024 * 1024
PACKET_LENGTHS = {0x01: 0x30, 0x03: 0x14, 0x04: 0x10,
                  0x06: 0x0C, 0x08: 0x08, 0x12: 0x20}

HELLO710 = bytes([
    0x02, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
])

LOADER_HELLO = struct.pack("<IIIIII", 0x02, 0x30, 0x02, 0x01, 0, 0) + b"\0" * 24
DONE = struct.pack("<II", 0x05, 0x08)
RESET_BYTE = b"\x13"

CONFIGURE_UFS = (
    b'<?xml version="1.0" encoding="UTF-8" ?>'
    b'<data><configure MemoryName="ufs" ZlpAwareHost="1" '
    b'MaxPayloadSizeToTargetInBytes="1048576" AlwaysValidate="0" '
    b'Verbose="0" /></data>'
)
CONFIGURE_EMMC = (
    b'<?xml version="1.0" encoding="UTF-8" ?>'
    b'<data><configure MemoryName="emmc" ZlpAwareHost="1" '
    b'MaxPayloadSizeToTargetInBytes="1048576" AlwaysValidate="0" '
    b'Verbose="0" /></data>'
)

SAHARA_NAMES = {
    0x01: "HELLO", 0x02: "HELLO_RESP", 0x03: "READ_DATA32",
    0x04: "END_IMAGE_TX", 0x05: "DONE", 0x06: "DONE_RESP",
    0x07: "RESET", 0x08: "RESET_RESP", 0x09: "MEMORY_DEBUG32",
    0x0A: "MEMORY_READ32", 0x0B: "READY", 0x0C: "SWITCH_MODE",
    0x0D: "EXECUTE", 0x0E: "EXECUTE_RESP", 0x0F: "EXECUTE_DATA",
    0x10: "MEMORY_DEBUG64", 0x11: "MEMORY_READ64",
    0x12: "READ_DATA64", 0x13: "RESET_STATE_MACHINE", 0x14: "WRITE_DATA",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(data: bytes, limit: int = 64) -> str:
    s = data[:limit].hex()
    return s + ("..." if len(data) > limit else "")


def log(msg: str) -> None:
    print(msg, flush=True)


@dataclass
class Resources:
    directory: str
    elf_header: bytes
    program_headers: bytes
    segment1: bytes
    segment2: bytes
    segment3: bytes
    zero_segment: bytes


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def check_resource(directory: str, name: str) -> Tuple[bool, bytes]:
    length, digest = RESOURCE_SPECS[name]
    path = os.path.join(directory, name)
    if not os.path.exists(path):
        log(f"  MISSING {path}")
        return False, b""
    data = read_file(path)
    ok = len(data) == length and sha256(data) == digest
    log(f"  {'OK   ' if ok else 'FAIL '} {name:44s} {len(data):#6x} B  {sha256(data)}")
    if len(data) != length:
        log(f"         expected length {length:#x}, got {len(data):#x}")
    if sha256(data) != digest:
        log(f"         expected sha256 {digest}")
    return ok, data


def load_resources(directory: str, segment1_override: Optional[str] = None,
                   segment1_hash: Optional[str] = None) -> Resources:
    if segment1_override and not segment1_hash:
        raise ValueError("--segment1 requires --segment1-hash")
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise SystemExit(f"resource directory not found: {directory}")
    loaded: Dict[str, bytes] = {}
    for name in RESOURCE_SPECS:
        if name == "common_zero_segment.bin" and not os.path.exists(os.path.join(directory, name)):
            data = bytes(ZERO_PBLEXP)
            length, digest = RESOURCE_SPECS[name]
            if len(data) != length or sha256(data) != digest:
                raise ValueError("generated zero resource does not match manifest")
            loaded[name] = data
            log(f"  OK    {name} (generated) sha256={digest}")
            continue
        if name == "segment1.bin" and segment1_override:
            path = os.path.abspath(segment1_override)
            data = read_file(path)
            expected_len = RESOURCE_SPECS[name][0]
            expected_hash = segment1_hash or RESOURCE_SPECS[name][1]
            ok = len(data) == expected_len and (
                not segment1_hash or sha256(data) == expected_hash
            )
            log(f"  {'OK   ' if ok else 'FAIL '} {path:44s} "
                f"{len(data):#6x} B  {sha256(data)}")
            if not ok:
                if len(data) != expected_len:
                    log(f"         expected length {expected_len:#x}")
                if segment1_hash and sha256(data) != segment1_hash:
                    log(f"         expected sha256 {segment1_hash}")
                raise SystemExit(f"segment1 check failed: {path}")
            loaded[name] = data
            continue
        expected_name = name
        if name == "segment1.bin" and segment1_hash:
            # Verify the resource-dir segment1 against a caller-provided hash
            # (used by custom/patched segment1 resource directories).
            path = os.path.join(directory, name)
            data = read_file(path)
            ok = len(data) == RESOURCE_SPECS[name][0] and sha256(data) == segment1_hash
            log(f"  {'OK   ' if ok else 'FAIL '} {name:44s} "
                f"{len(data):#6x} B  {sha256(data)}")
            if not ok:
                log(f"         expected sha256 {segment1_hash}")
                raise SystemExit(f"segment1 check failed: {path}")
            loaded[name] = data
            continue
        ok, data = check_resource(directory, expected_name)
        if not ok:
            raise SystemExit(f"resource check failed: {os.path.join(directory, expected_name)}")
        loaded[name] = data

    zero = loaded["common_zero_segment.bin"]
    if len(zero) != ZERO_PBLEXP or any(zero):
        raise SystemExit(f"{os.path.join(directory, 'common_zero_segment.bin')}: "
                         "not the 0xBF8 all-zero pblexp resource")

    return Resources(
        directory=directory,
        elf_header=loaded["oppo710_elf_header.bin"],
        program_headers=loaded["oppo710_program_headers.bin"],
        segment1=loaded["segment1.bin"],
        segment2=loaded["segment2.bin"],
        segment3=loaded["segment3.bin"],
        zero_segment=zero,
    )


def default_resources() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    local = os.path.join(here, "resources")
    if os.path.isdir(local):
        return local
    return os.path.join(os.path.dirname(here), "pblexp-oppo710")


def resolve_image(path: Optional[str]) -> Optional[str]:
    if path:
        return os.path.abspath(path)
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "devprg_710"),
        os.path.join(here, "resources", "devprg_710"),
        os.path.join(os.path.dirname(here), "pblexp-oppo710", "devprg_710"),
    ):
        if os.path.exists(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Port detection
# ---------------------------------------------------------------------------


def _list_ports_info() -> List[Tuple[str, str]]:
    try:
        from serial.tools import list_ports  # type: ignore
    except Exception:
        return []
    out: List[Tuple[str, str]] = []
    for p in list_ports.comports():
        out.append((p.device, f"{p.description} {p.hwid}"))
    return out


def _is_9008_text(text: str) -> bool:
    t = text.lower()
    return "9008" in t and any(word in t for word in ("05c6", "qualcomm", "qdloader"))


def find_9008_port() -> Optional[str]:
    candidates = [dev for dev, text in _list_ports_info() if _is_9008_text(text)]
    if len(candidates) > 1:
        raise RuntimeError("multiple serial EDL devices; select one with --port")
    return candidates[0] if candidates else None


def default_transport_order() -> Tuple[str, ...]:
    return ("usb", "serial") if sys.platform == "darwin" else ("serial", "usb")


def find_edl_interfaces(**filters) -> List[object]:
    if not usb_edl:
        raise RuntimeError(f"usb_edl unavailable: {_EDL_IMPORT_ERROR}")
    return [info for _dev, info in edl_find_devices(pid=0x9008, **filters)]


def list_ports_report() -> None:
    """Explicit inventory only: no qdl subprocesses or USB string probes."""
    log(f"platform default transport order: {default_transport_order()}")
    for dev, text in _list_ports_info():
        log(f"serial: {dev} {text}")
    try:
        infos = find_edl_interfaces()
        for info in infos:
            log(f"USB bus={info.bus} address={info.address} ports={info.port_numbers} "
                f"if={info.interface} in=0x{info.in_ep:02x} out=0x{info.out_ep:02x} "
                f"mps={info.in_maxpacket}/{info.out_maxpacket}")
        if not infos:
            log("USB: no 05c6:9008 EDL interface found")
    except RuntimeError as exc:
        log(f"USB unavailable: {exc}")


class DeviceNotFound(RuntimeError):
    pass


def resolve_endpoint(args: argparse.Namespace) -> Tuple[str, object]:
    requested = getattr(args, "port", "auto") or "auto"
    kind = getattr(args, "transport", "auto")
    usb_selector = getattr(args, "usb_bus", None) is not None or getattr(args, "usb_address", None) is not None
    if usb_selector:
        if kind == "serial" or requested != "auto":
            raise ValueError("USB selectors cannot be combined with a serial transport/port")
        kind = "usb"
    serial_path = getattr(args, "_serial_path", None)
    if serial_path:
        return "serial", serial_path
    if requested != "auto" and kind != "usb":
        return "serial", requested
    identity = getattr(args, "_usb_identity", None)
    order = ("usb",) if identity else default_transport_order()
    if kind in ("serial", "usb"):
        order = (kind,)
    errors = []
    for candidate_kind in order:
        if candidate_kind == "serial":
            found = find_9008_port()
            if found:
                return "serial", found
            continue
        filters = {}
        if identity:
            bus, ports, old_address = identity
            filters = {"bus": bus}
            filters.update({"port_numbers": ports} if ports else {"address": old_address})
        else:
            if getattr(args, "usb_bus", None) is not None:
                filters["bus"] = args.usb_bus
            if getattr(args, "usb_address", None) is not None:
                filters["address"] = args.usb_address
        try:
            infos = find_edl_interfaces(**filters)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        if identity:
            bus, ports, old_address = identity
            infos = [i for i in infos if i.bus == bus and
                     ((tuple(i.port_numbers) == ports) if ports else i.address == old_address)]
        else:
            bus, address = getattr(args, "usb_bus", None), getattr(args, "usb_address", None)
            infos = [i for i in infos if (bus is None or i.bus == bus) and
                     (address is None or i.address == address)]
        if len(infos) > 1:
            raise RuntimeError("multiple USB EDL interfaces; select --usb-bus and --usb-address")
        if infos:
            return "usb", infos[0]
    if errors and kind == "usb":
        raise RuntimeError("; ".join(errors))
    raise DeviceNotFound("no matching EDL transport found" + (": " + "; ".join(errors) if errors else ""))


def open_transport(args: argparse.Namespace, reopening: bool = False):
    timeout = args.reopen_timeout if reopening or getattr(args, "_reopening", False) else args.port_timeout
    deadline = time.monotonic() + timeout
    open_attempts = 0
    last = None
    while True:
        try:
            kind, info = resolve_endpoint(args)
        except (DeviceNotFound, OSError) as exc:
            if not isinstance(exc, DeviceNotFound) and not is_disconnect(exc):
                raise
            last = exc
        else:
            t = (SerialTransport(str(info), args.io_timeout) if kind == "serial" else
                 UsbEdlTransport(info, args.io_timeout, getattr(args, "usb_cdc", False)))
            try:
                open_attempts += 1
                t.open(1, 0)
            except Exception as exc:
                t.close()
                last = exc
                if open_attempts >= args.open_retries:
                    raise RuntimeError(f"could not open EDL transport: {exc}") from exc
            else:
                if kind == "usb":
                    args._usb_identity = (info.bus, tuple(info.port_numbers), info.address)
                else:
                    args._serial_path = str(info)
                log(f"transport: {t.description}")
                return t
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeviceNotFound(f"EDL discovery/open timed out after {timeout:g}s: {last}")
        time.sleep(min(args.open_retry_delay, remaining))


class ByteTransport:
    """Byte-stream transport used by the Sahara sequence."""

    description = "transport"

    def open(self, retries: int = 5, delay: float = 0.5) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def write(self, data: bytes) -> None:
        raise NotImplementedError

    def read(self, n: int) -> bytes:
        raise NotImplementedError

    def read_exact(self, n: int, timeout: float) -> bytes:
        buf = bytearray()
        end = time.monotonic() + timeout
        while len(buf) < n and time.monotonic() < end:
            chunk = self.read(n - len(buf))
            if chunk:
                buf += chunk
            else:
                time.sleep(0.01)
        return bytes(buf)

    def drain(self, seconds: float = 0.2) -> bytes:
        out = bytearray()
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                chunk = self.read(0x1000)
            except Exception:
                break
            if chunk:
                out += chunk
            else:
                time.sleep(0.01)
        return bytes(out)


class SerialTransport(ByteTransport):
    """pyserial /dev/cu.* transport."""

    def __init__(self, path: str, io_timeout: float = 0.2):
        self.path = path
        self.io_timeout = io_timeout
        self.ser = None
        self.description = f"serial {path}"

    def open(self, retries: int = 5, delay: float = 0.5) -> None:
        try:
            import serial  # type: ignore
        except Exception as exc:
            raise RuntimeError(f"pyserial is required: {exc}") from exc
        last: Optional[BaseException] = None
        for attempt in range(1, retries + 1):
            try:
                self.ser = serial.Serial(
                    self.path, 115200, timeout=self.io_timeout,
                    write_timeout=5,
                )
                self.ser.dtr = False
                self.ser.rts = False
                time.sleep(0.25)
                return
            except Exception as exc:  # PermissionError/SerialException
                last = exc
                log(f"open {self.path}: attempt {attempt}/{retries} failed: {exc}")
                time.sleep(delay)
        raise RuntimeError(f"could not open {self.path}: {last}")

    def close(self) -> None:
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass
            self.ser = None

    def write(self, data: bytes) -> None:
        if self.ser is None:
            raise RuntimeError("serial port is not open")
        self.ser.write(data)
        self.ser.flush()

    def read(self, n: int) -> bytes:
        if self.ser is None:
            raise RuntimeError("serial port is not open")
        return self.ser.read(n)


class UsbEdlTransport(ByteTransport):
    """The single packet-buffered native USB backend."""
    def __init__(self, info: object, io_timeout: float = 0.2, cdc_requests: bool = False):
        self.info = info
        self.io_timeout = io_timeout
        self.cdc_requests = cdc_requests
        self.edl = None
        self.description = (f"USB bus={info.bus} address={info.address} "
                            f"ports={info.port_numbers} if={info.interface}")

    def open(self, retries: int = 5, delay: float = 0.5) -> None:
        if self.edl is not None:
            return
        self.edl = UsbEdl(info=self.info, cdc_requests=self.cdc_requests)
        try:
            self.edl.open(retries=retries, delay=delay)
        except Exception:
            self.edl.close()
            self.edl = None
            raise

    def close(self) -> None:
        if self.edl is not None:
            self.edl.close()
            self.edl = None

    def write(self, data: bytes) -> None:
        if self.edl is None:
            raise RuntimeError("USB transport is not open")
        self.edl.write(data, timeout_ms=5000)

    def read(self, n: int) -> bytes:
        if self.edl is None:
            raise RuntimeError("USB transport is not open")
        return self.edl.read(n, timeout_ms=max(1, int(self.io_timeout * 1000)))

    def read_exact(self, n: int, timeout: float) -> bytes:
        if self.edl is None:
            raise RuntimeError("USB transport is not open")
        return self.edl.read_exact(n, timeout_ms=max(1, int(timeout * 1000)))


def parse_packet_header(raw: bytes) -> Tuple[int, int]:
    if len(raw) < 8:
        raise ValueError("short Sahara header")
    cmd, length = struct.unpack_from("<II", raw, 0)
    if length < 8 or length > 0x100000:
        raise ValueError(f"implausible Sahara length {length:#x} cmd={cmd:#x}")
    return cmd, length


def read_variable_packet(port: ByteTransport, timeout: float = 2.0) -> bytes:
    deadline = time.monotonic() + timeout
    head = port.read_exact(8, timeout)
    if len(head) != 8:
        raise TimeoutError(f"zero response header: got {len(head)} B")
    cmd, length = parse_packet_header(head)
    remaining = deadline - time.monotonic()
    if remaining <= 0 and length > 8:
        raise TimeoutError("Sahara packet body deadline expired")
    rest = port.read_exact(length - 8, max(remaining, 0.001))
    if len(rest) != length - 8:
        raise TimeoutError(f"zero response body: got {len(head)+len(rest)}/{length} B")
    return head + rest


# ---------------------------------------------------------------------------
# Host sequence
# ---------------------------------------------------------------------------


@dataclass
class HostStep:
    name: str
    data: bytes
    read_len: int = 0
    expect: str = ""
    repeat: int = 1
    expected_read: Optional[Tuple[int, int, int]] = None


def build_steps(res: Resources, zero_len: int = ZERO_PBLEXP,
                reset_count: int = 175) -> List[HostStep]:
    if not 1 <= reset_count <= 10000:
        raise ValueError("reset_count must be in 1..10000")
    if zero_len not in ZERO_CHOICES:
        raise ValueError(f"zero_len must be one of {ZERO_CHOICES}")
    if zero_len > len(res.zero_segment):
        raise ValueError("zero_len exceeds the zero resource")
    zero = res.zero_segment[:zero_len]
    if any(zero):
        raise ValueError("zero segment is not all zero")
    return [
        HostStep("hello710", HELLO710, 0x20,
                 "READ_DATA64 image=0xd offset=0x0 size=0x40", expected_read=(13, 0, 64)),
        HostStep("elf_header", res.elf_header, 0x20,
                 "READ_DATA64 image=0xd offset=0x40 size=0x4d0", expected_read=(13, 64, 1232)),
        HostStep("program_headers", res.program_headers, 0x20,
                 "READ_DATA64 image=0xd offset=0x1000 size=0x1000", expected_read=(13, 4096, 4096)),
        HostStep("segment1", res.segment1, 0x20,
                 "READ_DATA64 image=0xd offset=0x2000 size=0xbe8", expected_read=(13, 8192, 3048)),
        HostStep("zero_segment", zero, 0x10,
                 "END_IMAGE_TX status=0x08 (0xbf8) or HELLO 0x30 (0xbe8)"),
        HostStep("reset_state_machine", RESET_BYTE, 0x30,
                 "HELLO 0x30 (one per 0x13)", repeat=reset_count),
        HostStep("segment2", res.segment2, 0, "no read; handoff follows"),
        HostStep("segment3", res.segment3, 0, "no read; handoff follows"),
    ]


def print_steps(steps: Sequence[HostStep]) -> None:
    log("=" * 78)
    log("HOST -> DEVICE SEQUENCE (native macOS port)")
    log("=" * 78)
    total = 0
    for idx, step in enumerate(steps):
        data = step.data * step.repeat
        total += len(data)
        label = step.name + (f" x{step.repeat}" if step.repeat > 1 else "")
        log(f"[{idx:02d}] {label:24s} TX {len(data):#7x} B  "
            f"sha256={sha256(data)}")
        if step.read_len:
            log(f"       expect RX {step.read_len:#x} B: {step.expect}")
        else:
            log(f"       no read: {step.expect}")
    log(f"TOTAL TX: {total:#x} bytes ({total})")


def send_steps(port: ByteTransport, steps: Sequence[HostStep],
               read_timeout: float = 3.0, strict: bool = True,
               fast_resets: bool = False) -> None:
    def mismatch(message):
        if strict:
            raise RuntimeError(message)
        log(f"WARN {message}")

    # The macOS/libsub path sees the PBL's unsolicited HELLO (0x01/0x30)
    # on the bulk IN endpoint.  The Windows COM path's driver/open consumed
    # it.  Drain it before sending the host HELLO_RESP; otherwise the PBL's
    # minimal USB stack can NAK the first OUT transfer.
    if steps and steps[0].name == "hello710":
        pre = port.drain(0.2)
        if pre:
            log(f"initial RX {len(pre):#x} B (drained before Hello710): {pre[:8].hex()}")
    for step in steps:
        if fast_resets and step.name == "reset_state_machine" and step.repeat > 1:
            # Send the whole reset burst before reading.  A per-reset
            # round-trip costs ~0.2 s, which can exceed a boot-looping
            # device's EDL window; a burst keeps the sequence short.
            port.write(step.data * step.repeat)
            for index in range(step.repeat):
                raw = read_variable_packet(port, read_timeout)
                cmd, length = parse_packet_header(raw)
                expected_length = PACKET_LENGTHS.get(cmd)
                if expected_length is None or length != expected_length:
                    raise ValueError(f"invalid {SAHARA_NAMES.get(cmd, hex(cmd))} length {length:#x}")
                if cmd != 0x01:
                    mismatch(f"reset {index + 1}: expected HELLO, got {cmd:#x}")
                if (index + 1) % 25 == 0 or index + 1 == step.repeat:
                    log(f"reset {index + 1}/{step.repeat}")
            continue
        for index in range(step.repeat):
            port.write(step.data)
            if not step.read_len:
                continue
            raw = read_variable_packet(port, read_timeout)
            cmd, length = parse_packet_header(raw)
            expected_length = PACKET_LENGTHS.get(cmd)
            if expected_length is None or length != expected_length:
                raise ValueError(f"invalid {SAHARA_NAMES.get(cmd, hex(cmd))} length {length:#x}")
            if step.name == "reset_state_machine":
                if cmd != 0x01:
                    mismatch(f"reset {index + 1}: expected HELLO, got {cmd:#x}")
                if (index + 1) % 25 == 0 or index + 1 == step.repeat:
                    log(f"reset {index + 1}/{step.repeat}")
            elif step.name == "zero_segment":
                valid = False
                if cmd == 0x04:
                    image, status = struct.unpack_from("<II", raw, 8)
                    valid = image == IMAGE_ID and status == 8 and len(step.data) == ZERO_PBLEXP
                    log(f"RX zero END_IMAGE_TX image={image:#x} status={status:#x}")
                elif cmd == 0x01:
                    valid = len(step.data) == ZERO_PBL_REQUEST
                    log("RX zero HELLO (entry/reset, not success acknowledgement)")
                if not valid:
                    mismatch("unexpected zero-stage response for selected zero length")
            elif step.expected_read:
                if cmd != 0x12 or decode_read(raw) != step.expected_read:
                    mismatch(f"{step.name}: expected READ_DATA64 {step.expected_read}; got {raw.hex()}")
            if step.name != "reset_state_machine":
                log(f"TX {step.name}: {len(step.data):#x} B; RX {SAHARA_NAMES.get(cmd, hex(cmd))}")
    log("HOST SEQUENCE COMPLETE")


def run_host(args: argparse.Namespace, res: Resources) -> int:
    steps = build_steps(res, args.zero_len, args.reset_count)
    print_steps(steps)
    if args.dry_run:
        return 0
    port = open_transport(args)
    try:
        send_steps(port, steps, args.read_timeout, not args.relaxed,
                       getattr(args, "fast_resets", False))
    finally:
        port.close()
    log("host mode done; no programmer was uploaded")
    return 0


# ---------------------------------------------------------------------------
# Loader serve
# ---------------------------------------------------------------------------


@dataclass
class ServeResult:
    read_requests: int = 0
    bytes_served: int = 0
    end_image_tx: Optional[Tuple[int, int]] = None
    done_resp: bool = False
    done_status: Optional[int] = None
    firehose: bytes = b""
    opened_transport: str = ""


def try_parse(buf: bytearray) -> Optional[Tuple[int, int, bytes]]:
    if len(buf) < 8:
        return None
    cmd, length = parse_packet_header(buf[:8])
    if cmd not in PACKET_LENGTHS or length != PACKET_LENGTHS[cmd]:
        raise ValueError(f"unexpected Sahara command/length: {cmd:#x}/{length:#x}")
    if len(buf) < length:
        return None
    raw = bytes(buf[:length])
    del buf[:length]
    return cmd, length, raw


def decode_read(raw: bytes) -> Tuple[int, int, int]:
    cmd, length = parse_packet_header(raw)
    if len(raw) != length:
        raise ValueError("READ_DATA packet length mismatch")
    if cmd == 0x12 and length == 0x20:
        return struct.unpack_from("<QQQ", raw, 8)
    if cmd == 0x03 and length == 0x14:
        return struct.unpack_from("<III", raw, 8)
    raise ValueError(f"not a valid READ_DATA packet: cmd={cmd:#x} len={length:#x}")


def serve_chunk(image: bytes, off: int, size: int) -> bytes:
    if off < 0 or size <= 0 or size > MAX_IMAGE_REQUEST or off > len(image) or size > len(image) - off:
        raise ValueError(f"invalid programmer range offset={off:#x} size={size:#x} image={len(image):#x}")
    return image[off:off + size]


def read_programmer(path: str) -> bytes:
    image = read_file(path)
    if not image:
        raise ValueError("programmer image is empty")
    return image


def is_disconnect(exc: BaseException) -> bool:
    return (getattr(exc, "errno", None) in (errno.ENODEV, errno.ENXIO, errno.EIO) or
            getattr(exc, "backend_error_code", None) in (-4, -1))


def configure_exchange(port: ByteTransport, args: argparse.Namespace,
                       timeout: float) -> Tuple[ByteTransport, bytes]:
    payload = CONFIGURE_UFS if args.xml == "ufs" else CONFIGURE_EMMC
    deadline = time.monotonic() + timeout
    buf = bytearray()
    recovered = False
    need_write = True
    while time.monotonic() < deadline:
        try:
            if need_write:
                port.write(payload)
                log(f"TX configure ({args.xml}): {len(payload)} B")
                need_write = False
            chunk = port.read(0x10000)
            if chunk:
                buf += chunk
                if b"<response" in buf:
                    break
                if len(buf) > MAX_IMAGE_REQUEST:
                    raise ValueError("Firehose response exceeds 1 MiB")
        except Exception as exc:
            if is_disconnect(exc) and not args.no_reopen and not recovered:
                log(f"USB transition during configure: {exc}; reopening selected device")
                port.close()
                recovered = True
                try:
                    port = open_transport(args, reopening=True)
                except Exception as reopen_exc:
                    log(f"configure reopen failed: {reopen_exc}")
                    break
                need_write = True
                buf.clear()
                continue
            log(f"configure failed: {exc}")
            break
    return port, bytes(buf)


def run_serve(args: argparse.Namespace, image_path: str,
              image_data: Optional[bytes] = None) -> int:
    image = read_programmer(image_path) if image_data is None else image_data
    if not image:
        raise ValueError("programmer image is empty")
    log(f"image: {image_path} ({len(image):#x} B) sha256={sha256(image)}")
    if args.dry_run:
        log(f"loader HELLO_RESP: {len(LOADER_HELLO):#x} B; xml={args.xml}")
        return 0
    port = open_transport(args)
    if args.serve_settle:
        time.sleep(args.serve_settle)
    result = ServeResult(opened_transport=port.description)
    buf = bytearray()
    deadline = time.monotonic() + args.total_timeout
    awaiting_done = False
    rejected = False
    recovered = False
    need_hello = not args.no_hello
    try:
        while time.monotonic() < deadline and not result.done_resp and not rejected:
            try:
                if need_hello:
                    # The libusb path can see the PBL/loader's unsolicited
                    # HELLO on the new handle, just like the host phase.  The
                    # Windows COM open consumed it.  Drain it before sending
                    # LOADER_HELLO so the minimal USB stack is ready for OUT.
                    pre = port.drain(getattr(args, "serve_drain", 0.5))
                    if pre:
                        log(f"initial loader RX {len(pre):#x} B "
                            f"(drained before LOADER_HELLO): {pre[:8].hex()}")
                    port.write(LOADER_HELLO)
                    need_hello = False
                chunk = port.read(0x10000)
            except Exception as exc:
                if is_disconnect(exc) and result.read_requests == 0 and not args.no_reopen and not recovered:
                    port.close()
                    recovered = True
                    port = open_transport(args, reopening=True)
                    result.opened_transport = port.description
                    buf.clear()
                    need_hello = not args.no_hello
                    continue
                log(f"Sahara read failed: {exc}")
                break
            if not chunk:
                continue
            buf += chunk
            while buf:
                pkt = try_parse(buf)
                if pkt is None:
                    break
                cmd, length, raw = pkt
                if cmd == 0x01:
                    if awaiting_done:
                        raise ValueError("HELLO before DONE_RESP")
                    port.write(LOADER_HELLO)
                elif cmd in (0x12, 0x03):
                    if awaiting_done:
                        raise ValueError("READ_DATA before DONE_RESP")
                    image_id, off, size = decode_read(raw)
                    if image_id != IMAGE_ID:
                        raise ValueError(f"unsupported programmer image id {image_id:#x}")
                    data = serve_chunk(image, off, size)
                    port.write(data)
                    result.read_requests += 1
                    result.bytes_served += len(data)
                elif cmd == 0x04:
                    if awaiting_done:
                        raise ValueError("duplicate END_IMAGE_TX before DONE_RESP")
                    image_id, status = struct.unpack_from("<II", raw, 8)
                    if image_id != IMAGE_ID:
                        raise ValueError(f"unexpected END_IMAGE_TX image {image_id:#x}")
                    result.end_image_tx = image_id, status
                    log(f"RX END_IMAGE_TX image={image_id:#x} status={status:#x}")
                    if status != 0:
                        rejected = True
                        break
                    if not result.read_requests:
                        raise ValueError("END_IMAGE_TX success before any image requests")
                    awaiting_done = True
                    port.write(DONE)
                elif cmd == 0x06:
                    if not awaiting_done:
                        raise ValueError("DONE_RESP without accepted image and DONE")
                    status = struct.unpack_from("<I", raw, 8)[0]
                    if status not in (0, 1):
                        raise ValueError(f"invalid DONE_RESP status {status}")
                    result.done_status = status
                    result.done_resp = status == 1
                    awaiting_done = False
                    log(f"RX DONE_RESP: {'complete' if status else 'pending'}")
                    if result.done_resp:
                        break
                else:
                    raise ValueError(f"unexpected Sahara command {cmd:#x}")
        if result.done_resp and args.xml != "none":
            port, result.firehose = configure_exchange(port, args, 8.0)
    finally:
        port.close()
    log(f"READ_DATA requests: {result.read_requests}; bytes served: {result.bytes_served:#x}")
    log(f"END_IMAGE_TX: {result.end_image_tx}; DONE status: {result.done_status}")
    if result.done_resp and (args.xml == "none" or b"<response" in result.firehose):
        log("RESULT: Sahara complete" + ("; programmer answered Firehose" if result.firehose else ""))
        return 0
    if result.end_image_tx and result.end_image_tx[1] == 0:
        log("RESULT: image accepted; Sahara completion or requested Firehose response missing")
        return 2
    log("RESULT: image rejected or Sahara transfer incomplete")
    return 3


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------


def run_ping(args: argparse.Namespace) -> int:
    port = open_transport(args)
    try:
        port, buf = configure_exchange(port, args, args.timeout)
    finally:
        port.close()
    if b"<response" in buf:
        log("RESULT: programmer responded (execution ping; ACK/NAK is not a configuration verdict)")
        return 0
    log("RESULT: no Firehose response")
    return 2


# ---------------------------------------------------------------------------
# All: host + handoff + serve
# ---------------------------------------------------------------------------


def run_all(args: argparse.Namespace, res: Resources, image_path: str) -> int:
    image = read_programmer(image_path)
    steps = build_steps(res, args.zero_len, args.reset_count)
    print_steps(steps)
    if args.dry_run:
        log(f"handoff: {args.handoff_delay:.2f}s, then serve {image_path}")
        return 0
    port = open_transport(args)
    try:
        send_steps(port, steps, args.read_timeout, not args.relaxed,
                       getattr(args, "fast_resets", False))
    finally:
        port.close()
    log(f"handoff: waiting {args.handoff_delay:.2f}s")
    time.sleep(args.handoff_delay)
    # The PBL may re-enumerate; resolve again rather than trusting the old path.
    args._reopening = True
    return run_serve(args, image_path, image_data=image)


# ---------------------------------------------------------------------------
# Offline checks / self-test
# ---------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    log("RESOURCE CHECK")
    try:
        load_resources(args.resources, args.segment1, args.segment1_hash)
    except SystemExit:
        return 1
    image = resolve_image(args.image)
    if image:
        data = read_programmer(image)
        log(f"  READABLE    {os.path.basename(image):44s} {len(data):#6x} B  "
            f"{sha256(data)}")
    else:
        log("  (no programmer image found; pass --image for the serve test)")
    return 0


def cmd_dry(args: argparse.Namespace) -> int:
    mode = args.mode if args.cmd == "dry-run" else args.cmd
    if mode in ("host", "all"):
        res = load_resources(args.resources, args.segment1, args.segment1_hash)
        print_steps(build_steps(res, args.zero_len, args.reset_count))
    if mode in ("serve", "all"):
        image = resolve_image(args.image)
        if not image:
            raise ValueError("no programmer image found; pass --image")
        data = read_programmer(image)
        log(f"serve image: {image} ({len(data):#x} B) sha256={sha256(data)}")
        log(f"loader HELLO_RESP: {len(LOADER_HELLO):#x} B; xml={args.xml}")
    if mode == "all":
        log(f"handoff: {args.handoff_delay:.2f}s")
    if mode == "ping":
        log(f"configure XML ({args.xml}): {len(CONFIGURE_UFS if args.xml == 'ufs' else CONFIGURE_EMMC)} B")
    return 0


def self_test() -> int:
    res = Resources("synthetic", bytes(0x40), bytes(0x4d0), bytes(0x1000),
                    bytes(0x3f0), bytes(0x3a8), bytes(ZERO_PBLEXP))
    steps = build_steps(res, ZERO_PBLEXP, 175)
    assert [s.name for s in steps][-2:] == ["segment2", "segment3"]
    assert sum(len(s.data) * s.repeat for s in steps) == (
        0x30 + 0x40 + 0x4d0 + 0x1000 + 0xbf8 + 175 + 0x3f0 + 0x3a8
    )
    # packet parser
    pkt = struct.pack("<IIQQQ", 0x12, 0x20, 13, 0x40, 0x4d0)
    buf = bytearray(pkt)
    parsed = try_parse(buf)
    assert parsed and parsed[0] == 0x12
    assert decode_read(parsed[2]) == (13, 0x40, 0x4d0)
    pkt32 = struct.pack("<IIIII", 0x03, 0x14, 13, 0x40, 0x4D0)
    parsed32 = try_parse(bytearray(pkt32))
    assert parsed32 and decode_read(parsed32[2]) == (13, 0x40, 0x4D0)
    # bounded image ranges
    img = bytes(range(256)) * 4
    assert serve_chunk(img, 0, 64) == img[:64]
    for offset, size in ((2000, 16), (1020, 10)):
        try:
            serve_chunk(img, offset, size)
        except ValueError:
            pass
        else:
            raise AssertionError("out-of-range request accepted")
    # loader hello layout
    assert struct.unpack_from("<II", LOADER_HELLO, 0) == (2, 0x30)
    assert struct.unpack_from("<IIII", LOADER_HELLO, 8) == (2, 1, 0, 0)
    # port parser unit
    assert _is_9008_text("USB VID:PID=05C6:9008")
    assert _is_9008_text("Qualcomm HS-USB QDLoader 9008")
    assert not _is_9008_text("USB serial")
    assert default_transport_order() == (
        ("usb", "serial") if sys.platform == "darwin" else ("serial", "usb")
    )
    # zero resource
    assert len(res.zero_segment) == ZERO_PBLEXP and not any(res.zero_segment)
    # Host sequence against an in-memory transport: proves the 175 reset
    # writes are individually paired with HELLO reads (no coalescing).
    class MockTransport(ByteTransport):
        def __init__(self, data: bytes):
            self.data = bytearray(data)
            self.writes = []

        def write(self, data: bytes) -> None:
            self.writes.append(bytes(data))

        def read(self, n: int) -> bytes:
            if not self.data:
                return b""
            chunk = bytes(self.data[:n])
            del self.data[:n]
            return chunk

        def drain(self, seconds: float = 0.2) -> bytes:
            return b""

    hello = struct.pack("<IIIIII", 0x01, 0x30, 0x02, 0x02, 0x400, 0) + b"\0" * 24
    responses = bytearray()
    for off, size in ((0, 0x40), (0x40, 0x4d0), (0x1000, 0x1000),
                      (0x2000, 0xbe8)):
        responses += struct.pack("<IIQQQ", 0x12, 0x20, 0xd, off, size)
    responses += struct.pack("<IIII", 0x04, 0x10, 0xd, 0x8)
    responses += hello * 175
    mock = MockTransport(bytes(responses))
    send_steps(mock, steps, 0.2, strict=True)
    assert len(mock.writes) == 4 + 1 + 175 + 1 + 1
    assert mock.writes[-2] == res.segment2
    assert mock.writes[-1] == res.segment3
    log("SELF-TEST: PASS (offline; no device opened, mock host sequence)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def positive_seconds(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return result


def nonnegative_seconds(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number")
    return result


def bounded_count(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 10000:
        raise argparse.ArgumentTypeError("must be in 1..10000")
    return result


def usb_bus_number(value: str) -> int:
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("USB bus must be nonnegative")
    return result


def usb_device_address(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 127:
        raise argparse.ArgumentTypeError("USB address must be in 1..127")
    return result


def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--transport", choices=["auto", "serial", "usb"],
                   default="auto",
                   help="auto (USB on macOS, serial elsewhere), serial, or usb")
    p.add_argument("--port", default="auto",
                   help="serial port path or 'auto' (default: auto; ignored "
                        "for --transport usb)")
    p.add_argument("--usb-cdc", action="store_true",
                   help="experimental opt-in CDC class requests (not proven required)")
    p.add_argument("--usb-bus", type=usb_bus_number, default=None,
                   help="optional libusb bus number for USB selection")
    p.add_argument("--usb-address", type=usb_device_address, default=None,
                   help="optional libusb device address for USB selection")
    p.add_argument("--resources", default=default_resources(),
                   help="resource directory (default: ./resources)")
    p.add_argument("--segment1", default=None,
                   help="override segment1.bin (e.g. a patched payload)")
    p.add_argument("--segment1-hash", default=None,
                   help="expected SHA-256 for the segment1 resource/override")
    p.add_argument("--io-timeout", type=positive_seconds, default=0.2,
                   help="serial read timeout in seconds")
    p.add_argument("--port-timeout", type=positive_seconds, default=8.0,
                   help="seconds to wait for auto-detection")
    p.add_argument("--reopen-timeout", type=positive_seconds, default=10.0,
                   help="seconds to wait for re-enumeration")
    p.add_argument("--open-retries", type=bounded_count, default=5)
    p.add_argument("--open-retry-delay", type=positive_seconds, default=0.5)
    p.add_argument("--handoff-delay", type=nonnegative_seconds, default=1.0,
                   help="delay after segment3 before handoff/serve")
    p.add_argument("--serve-settle", type=nonnegative_seconds, default=0.5,
                   help="settle delay after the loader-port open before HELLO")
    p.add_argument("--serve-drain", type=nonnegative_seconds, default=0.5,
                   help="drain an unsolicited loader HELLO before LOADER_HELLO")
    p.add_argument("--zero-len", type=lambda s: int(s, 0), default=ZERO_PBLEXP,
                   choices=ZERO_CHOICES)
    p.add_argument("--reset-count", type=bounded_count, default=175)
    p.add_argument("--read-timeout", type=positive_seconds, default=3.0)
    p.add_argument("--relaxed", action="store_true",
                   help="allow well-formed unexpected host responses; framing/timeouts still fail")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-reopen", action="store_true",
                   help="serve: do not reopen after a USB transition")
    p.add_argument("--image", default=None,
                   help="programmer image path (serve/all)")
    p.add_argument("--xml", choices=["ufs", "emmc", "none"], default="ufs")
    p.add_argument("--fast-resets", action="store_true",
                   help="send the 0x13 reset burst in one write (faster; for "
                        "devices whose EDL window is short)")
    p.add_argument("--no-hello", action="store_true",
                   help="serve: skip unsolicited initial HELLO_RESP; still answer device HELLO")
    p.add_argument("--total-timeout", type=positive_seconds, default=90.0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_host = sub.add_parser("host", help="send the fixed pblexp host sequence")
    add_common(p_host)

    p_serve = sub.add_parser("serve", help="serve the programmer after handoff")
    add_common(p_serve)

    p_all = sub.add_parser("all", help="host sequence, handoff, then serve")
    add_common(p_all)

    p_ping = sub.add_parser("ping", help="send benign Firehose configure")
    add_common(p_ping)
    p_ping.add_argument("--timeout", type=positive_seconds, default=10.0)

    p_check = sub.add_parser("check-resources")
    p_check.add_argument("--resources", default=default_resources())
    p_check.add_argument("--segment1", default=None)
    p_check.add_argument("--segment1-hash", default=None)
    p_check.add_argument("--image", default=None)

    p_dry = sub.add_parser("dry-run")
    add_common(p_dry)
    p_dry.add_argument("--mode", choices=["host", "serve", "all", "ping"],
                       default="host")

    sub.add_parser("self-test")
    sub.add_parser("list-ports")

    args = ap.parse_args(argv)
    if (getattr(args, "usb_bus", None) is not None or getattr(args, "usb_address", None) is not None) and (
            getattr(args, "transport", "auto") == "serial" or getattr(args, "port", "auto") != "auto"):
        ap.error("USB selectors cannot be combined with a serial transport/port")
    if (args.cmd == "ping" or (args.cmd == "dry-run" and args.mode == "ping")) and args.xml == "none":
        ap.error("ping requires --xml ufs or emmc")
    if getattr(args, "usb_cdc", False):
        logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")

    try:
        if args.cmd == "self-test":
            return self_test()
        if args.cmd == "list-ports":
            list_ports_report()
            return 0
        if args.cmd == "check-resources":
            return cmd_check(args)
        if args.cmd == "dry-run" or getattr(args, "dry_run", False):
            return cmd_dry(args)
        if args.cmd == "ping":
            return run_ping(args)
        image = resolve_image(args.image)
        if args.cmd in ("serve", "all"):
            if not image:
                raise ValueError("no programmer image found; pass --image PATH")
            # Preflight before either host resource upload or device selection.
            read_programmer(image)
        if args.cmd == "serve":
            return run_serve(args, image)
        res = load_resources(args.resources, args.segment1, args.segment1_hash)
        if args.cmd == "host":
            return run_host(args, res)
        if args.cmd == "all":
            return run_all(args, res, image)
        raise ValueError(f"unknown command {args.cmd}")
    except (Exception, SystemExit) as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
