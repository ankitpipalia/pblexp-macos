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

macOS port detection uses pyserial's list_ports first, then ioreg and
system_profiler as fallbacks.  Use --port to override.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import usb.core
    import usb.util
except Exception as _usb_exc:  # optional libusb/pyusb fallback
    usb = None
    _USB_IMPORT_ERROR = _usb_exc
else:
    _USB_IMPORT_ERROR = None

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
    0x12: "READ_DATA64", 0x13: "RESET_STATE_MACHINE", 0x14: "DONE64",
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
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise SystemExit(f"resource directory not found: {directory}")
    loaded: Dict[str, bytes] = {}
    for name in RESOURCE_SPECS:
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
            # (used by the patched auth-bypass resource directories).
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

    # A missing zero resource is safe to generate; a present non-zero blob is
    # the known-bad .NET manifest extraction and must not be used.
    zero_path = os.path.join(directory, "common_zero_segment.bin")
    if not os.path.exists(zero_path):
        loaded["common_zero_segment.bin"] = b"\x00" * ZERO_PBLEXP
        log(f"  OK    common_zero_segment (generated)             "
            f"{ZERO_PBLEXP:#6x} B  {sha256(loaded['common_zero_segment.bin'])}")
    zero = loaded["common_zero_segment.bin"]
    if len(zero) != ZERO_PBLEXP or any(zero):
        raise SystemExit(f"{zero_path}: not the 0xBF8 all-zero pblexp resource")

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
    return (
        "9008" in t
        or "qdloader" in t
        or "qualcomm" in t
        or ("05c6" in t and "9008" in t)
    )


def _ioreg_candidates() -> List[str]:
    """Parse ioreg for a 05c6:9008 USB device and its callout device."""
    try:
        raw = subprocess.run(
            ["ioreg", "-p", "IOUSB", "-l", "-w", "0"],
            capture_output=True, text=True, timeout=8,
        ).stdout
    except Exception:
        return []
    if not raw:
        return []
    # IOReg prints a tree; split at device nodes so a sibling's callout does
    # not get attributed to the wrong device.
    blocks = re.split(r"(?=\n\s*\+\-o\s)", raw)
    found: List[str] = []
    for block in blocks:
        low = block.lower()
        product = "9008" in low or "qdloader" in low
        vendor = "idvendor\" = 1478" in low or "0x05c6" in low or "05c6" in low
        prodid = "idproduct\" = 36872" in low or "0x9008" in low or "9008" in low
        if not ((product or prodid) and (vendor or product)):
            continue
        m = re.search(r'"IOCalloutDevice"\s*=\s*"([^"]+)"', block)
        if m:
            found.append(m.group(1))
    # Deduplicate while preserving order.
    return list(dict.fromkeys(found))


def _system_profiler_candidates() -> List[str]:
    try:
        raw = subprocess.run(
            ["system_profiler", "SPUSBDataType", "-json"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return []
    try:
        import json
        data = json.loads(raw)
    except Exception:
        return []
    found: List[str] = []

    def walk(node):
        if isinstance(node, dict):
            text = " ".join(str(v) for v in node.values() if isinstance(v, (str, int)))
            if _is_9008_text(text):
                for key in ("bsd_name", "IOCalloutDevice", "device"):
                    v = node.get(key)
                    if isinstance(v, str) and v.startswith("/dev/"):
                        found.append(v)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return list(dict.fromkeys(found))


def find_9008_port() -> Optional[str]:
    """Return the first candidate 9008 serial port, or None."""
    for dev, text in _list_ports_info():
        if _is_9008_text(text) or dev.lower().startswith("/dev/cu."):
            if _is_9008_text(text):
                return dev
    for dev in _ioreg_candidates() + _system_profiler_candidates():
        if dev:
            return dev
    return None


@dataclass
class UsbCandidate:
    bus: int
    address: int
    serial: str = ""
    product: str = ""

    @property
    def label(self) -> str:
        bits = [f"bus {self.bus} address {self.address}"]
        if self.product:
            bits.append(self.product)
        if self.serial:
            bits.append(f"serial {self.serial}")
        return "USB 05c6:9008 (" + ", ".join(bits) + ")"


def find_9008_usb(bus: Optional[int] = None,
                  address: Optional[int] = None) -> List[UsbCandidate]:
    """Return optional pyusb/libusb candidates for VID 05c6 PID 9008."""
    if usb is None:
        return []
    try:
        devices = usb.core.find(
            find_all=True, idVendor=0x05C6, idProduct=0x9008
        )
    except Exception:
        return []
    out: List[UsbCandidate] = []
    for dev in devices or []:
        try:
            if bus is not None and int(dev.bus) != bus:
                continue
            if address is not None and int(dev.address) != address:
                continue
            try:
                serial = dev.serial_number or ""
            except Exception:
                serial = ""
            try:
                product = dev.product or ""
            except Exception:
                product = ""
            out.append(UsbCandidate(int(dev.bus), int(dev.address),
                                    serial, product))
        except Exception:
            continue
    return out


def default_transport_order() -> Tuple[str, ...]:
    """macOS exposes QDLoader as vendor-specific USB, not a /dev/cu node."""
    return ("usb", "serial") if sys.platform == "darwin" else ("serial", "usb")


def qdl_list_output() -> str:
    try:
        r = subprocess.run(["qdl", "list"], capture_output=True, text=True,
                           timeout=6)
        return (r.stdout + r.stderr).strip()
    except Exception as exc:
        return f"(qdl list unavailable: {exc})"


def qdl_sees_9008() -> bool:
    out = qdl_list_output().lower()
    return bool(out) and "no devices found" not in out and (
        "9008" in out or "05c6" in out or "qualcomm" in out
    )


def find_edl_interfaces() -> List[object]:
    """Use usb_edl.find_devices() when available (preferred macOS path)."""
    if not usb_edl:
        return []
    try:
        return [info for _dev, info in edl_find_devices()]
    except Exception:
        return []


def _is_edl_interface(info: object) -> bool:
    return usb_edl is not None and isinstance(info, EdlInterface)


def list_ports_report() -> None:
    log(f"platform default transport order: {default_transport_order()}")
    info = _list_ports_info()
    log("serial candidates (pyserial):")
    if not info:
        log("  (none)")
    for dev, text in info:
        log(f"  {dev}  {text}")
    log("usb candidates (usb_edl/libusb 05c6:9008):")
    edl_infos = find_edl_interfaces()
    if not usb_edl:
        log(f"  usb_edl unavailable: {_EDL_IMPORT_ERROR}")
    elif not edl_infos:
        log("  (none)")
    else:
        for i in edl_infos:
            log(f"  if={i.interface} in=0x{i.in_ep:02x} out=0x{i.out_ep:02x} "
                f"mps={i.in_maxpacket}/{i.out_maxpacket} "
                f"serial={i.serial!r} product={i.product!r}")
    log("usb candidates (raw pyusb fallback):")
    usb_candidates = find_9008_usb()
    if usb is None:
        log(f"  unavailable: {_USB_IMPORT_ERROR}")
    elif not usb_candidates:
        log("  (none)")
    else:
        for c in usb_candidates:
            log(f"  {c.label}")
    qdl = qdl_list_output()
    log("qdl list:")
    for line in qdl.splitlines() or ["(empty)"]:
        log(f"  {line}")
    log("ioreg serial 9008 candidates (fallback only):")
    for dev in _ioreg_candidates():
        log(f"  {dev}")
    log("system_profiler serial 9008 candidates (fallback only):")
    for dev in _system_profiler_candidates():
        log(f"  {dev}")
    serial = find_9008_port()
    if sys.platform == "darwin" and edl_infos:
        log(f"selected: usb if={edl_infos[0].interface} "
            f"serial={edl_infos[0].serial!r} (usb_edl)")
    elif serial:
        log(f"selected: serial {serial}")
    elif edl_infos:
        log(f"selected: usb if={edl_infos[0].interface} "
            f"serial={edl_infos[0].serial!r} (usb_edl)")
    elif usb_candidates:
        log(f"selected: usb {usb_candidates[0].label}")
    else:
        log("selected: (none)")


def resolve_endpoint(args: argparse.Namespace
                     ) -> Tuple[str, object]:
    """Return ('serial', path) or ('usb', UsbCandidate).

    macOS QDLoader 9008 is a vendor-specific USB device (0x05c6:0x9008,
    interface class 0xFF) with bulk endpoints; it has no /dev/cu node.  Auto
    mode therefore tries USB first on Darwin and serial first elsewhere.
    An explicit /dev/cu path still selects serial.
    """
    requested = getattr(args, "port", "auto") or "auto"
    kind = getattr(args, "transport", "auto")
    if requested != "auto" and kind != "usb":
        return "serial", requested

    order = default_transport_order()
    if kind == "serial":
        order = ("serial",)
    elif kind == "usb":
        order = ("usb",)

    for candidate_kind in order:
        if candidate_kind == "usb":
            bus = getattr(args, "usb_bus", None)
            addr = getattr(args, "usb_address", None)
            if usb_edl and bus is None and addr is None:
                infos = find_edl_interfaces()
                if infos:
                    return "usb", infos[0]
            candidates = find_9008_usb(bus, addr)
            if candidates:
                return "usb", candidates[0]
        else:
            p = find_9008_port()
            if p:
                return "serial", p

    if kind == "serial":
        list_ports_report()
        raise RuntimeError(
            "no serial Qualcomm 9008 port found; on macOS the QDLoader "
            "interface is normally vendor-specific USB, so use "
            "--transport usb (default on macOS), or pass an explicit "
            "/dev/cu.* path only if a driver creates one."
        )
    if kind == "usb":
        if usb is None:
            raise RuntimeError(
                "USB transport requested but pyusb/libusb is unavailable: "
                f"{_USB_IMPORT_ERROR}.  Install with "
                "`python3 -m pip install --user pyusb` (libusb is provided by "
                "macOS/Homebrew), or use --transport serial on Windows."
            )
        list_ports_report()
        if qdl_sees_9008():
            raise RuntimeError(
                "qdl sees a 05c6:9008 device but pyusb did not enumerate it. "
                "Check libusb/permissions (run `qdl list`), or use the qdl "
                "CLI directly."
            )
        raise RuntimeError(
            "no USB 05c6:9008 device found; check the cable and that the "
            "PBL is in EDL.  A wedged PBL needs a power-button reset."
        )

    list_ports_report()
    if qdl_sees_9008() and usb is None:
        raise RuntimeError(
            "qdl sees a 05c6:9008 device, but pyusb/libusb is unavailable. "
            "Install pyusb (`python3 -m pip install --user pyusb`) and retry."
        )
    raise RuntimeError(
        "no Qualcomm 9008 transport found.  On macOS use --transport usb "
        "(pyusb/libusb; default) or install a driver for --transport serial. "
        "On Windows use --transport serial --port COMx."
    )


def open_transport(args: argparse.Namespace):
    kind, info = resolve_endpoint(args)
    if kind == "serial":
        t = SerialTransport(str(info), args.io_timeout)
    elif _is_edl_interface(info):
        t = UsbEdlTransport(info, args.io_timeout)  # type: ignore[arg-type]
    else:
        t = UsbTransport(info, args.io_timeout)  # type: ignore[arg-type]
    t.open(args.open_retries, args.open_retry_delay)
    log(f"transport: {t.description}")
    return t


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


class UsbTransport(ByteTransport):
    """Optional pyusb/libusb bulk transport for VID 05c6 PID 9008.

    macOS may not create a /dev/cu node for the QDLoader interface.  This is a
    deliberately small fallback: it finds the vendor interface's bulk IN/OUT
    endpoints and carries the same Sahara bytes.  If pyusb/libusb is missing,
    selection fails with an explicit message; serial remains the default.
    """

    def __init__(self, candidate: UsbCandidate, io_timeout: float = 0.2):
        self.candidate = candidate
        self.io_timeout = io_timeout
        self.dev = None
        self.ep_in = None
        self.ep_out = None
        self.cfg = None
        self.interface = None
        self.description = candidate.label

    def open(self, retries: int = 5, delay: float = 0.5) -> None:
        if usb is None:
            raise RuntimeError(
                "pyusb/libusb is unavailable: "
                f"{_USB_IMPORT_ERROR}.  Install pyusb and libusb, or use "
                "--transport serial with a /dev/cu.* port."
            )
        last: Optional[BaseException] = None
        for attempt in range(1, retries + 1):
            try:
                self.dev = usb.core.find(
                    idVendor=0x05C6, idProduct=0x9008,
                    bus=self.candidate.bus, address=self.candidate.address,
                )
                if self.dev is None:
                    raise RuntimeError("device disappeared during open")
                try:
                    self.dev.set_configuration()
                except Exception:
                    # Already configured is normal on some backends.
                    pass
                self.cfg = self.dev.get_active_configuration()
                interfaces = list(self.cfg)
                preferred = [
                    i for i in interfaces
                    if int(getattr(i, "bInterfaceClass", -1)) == 0xFF
                    and int(getattr(i, "bInterfaceSubClass", -1)) == 0xFF
                    and int(getattr(i, "bInterfaceProtocol", -1)) == 0xFF
                ]
                ordered = preferred + [i for i in interfaces if i not in preferred]
                self.interface = None
                self.ep_in = None
                self.ep_out = None
                for intf in ordered:
                    in_ep = usb.util.find_descriptor(
                        intf,
                        custom_match=lambda e: (
                            usb.util.endpoint_direction(e.bEndpointAddress)
                            == usb.util.ENDPOINT_IN
                            and usb.util.endpoint_type(e.bmAttributes)
                            == usb.util.ENDPOINT_TYPE_BULK
                        ),
                    )
                    out_ep = usb.util.find_descriptor(
                        intf,
                        custom_match=lambda e: (
                            usb.util.endpoint_direction(e.bEndpointAddress)
                            == usb.util.ENDPOINT_OUT
                            and usb.util.endpoint_type(e.bmAttributes)
                            == usb.util.ENDPOINT_TYPE_BULK
                        ),
                    )
                    if in_ep is not None and out_ep is not None:
                        self.interface = intf
                        self.ep_in = in_ep
                        self.ep_out = out_ep
                        break
                if self.interface is None:
                    raise RuntimeError(
                        "no vendor-specific/bulk IN+OUT interface found; "
                        "interfaces=" + ",".join(
                            f"{int(getattr(i, 'bInterfaceNumber', -1))}:"
                            f"class{int(getattr(i, 'bInterfaceClass', -1)):#x}"
                            for i in interfaces
                        )
                    )
                try:
                    if self.dev.is_kernel_driver_active(self.interface.bInterfaceNumber):
                        self.dev.detach_kernel_driver(self.interface.bInterfaceNumber)
                except Exception:
                    pass
                try:
                    usb.util.claim_interface(self.dev, self.interface)
                except Exception as exc:
                    raise RuntimeError(f"claim interface failed: {exc}") from exc
                time.sleep(0.1)
                return
            except Exception as exc:
                last = exc
                log(f"open USB {self.candidate.label}: attempt "
                    f"{attempt}/{retries} failed: {exc}")
                self.close()
                time.sleep(delay)
        raise RuntimeError(f"could not open USB 05c6:9008: {last}")

    def close(self) -> None:
        if self.dev is not None and usb is not None:
            try:
                if self.interface is not None:
                    usb.util.release_interface(self.dev, self.interface)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(self.dev)
            except Exception:
                pass
        self.dev = None
        self.ep_in = None
        self.ep_out = None
        self.interface = None

    def write(self, data: bytes) -> None:
        if self.ep_out is None:
            raise RuntimeError("USB transport is not open")
        off = 0
        while off < len(data):
            try:
                n = self.ep_out.write(
                    data[off:], timeout=max(1, int(self.io_timeout * 5000))
                )
            except usb.core.USBTimeoutError as exc:
                raise RuntimeError(f"USB bulk OUT timeout: {exc}") from exc
            except usb.core.USBError as exc:
                raise RuntimeError(f"USB bulk OUT error: {exc}") from exc
            if not n:
                raise RuntimeError("USB bulk OUT wrote 0 bytes")
            off += int(n)

    def read(self, n: int) -> bytes:
        if self.ep_in is None:
            raise RuntimeError("USB transport is not open")
        try:
            data = self.ep_in.read(
                n, timeout=max(1, int(self.io_timeout * 1000))
            )
            return bytes(data)
        except usb.core.USBTimeoutError:
            return b""
        except usb.core.USBError as exc:
            raise RuntimeError(f"USB bulk IN error: {exc}") from exc


class UsbEdlTransport(ByteTransport):
    """Adapter around the shared usb_edl.UsbEdl transport."""

    def __init__(self, info: object, io_timeout: float = 0.2):
        self.info = info
        self.io_timeout = io_timeout
        self.edl = None
        self.description = (
            f"USB usb_edl if={getattr(info, 'interface', '?')} "
            f"in=0x{getattr(info, 'in_ep', 0):02x} "
            f"out=0x{getattr(info, 'out_ep', 0):02x} "
            f"serial={getattr(info, 'serial', '')!r}"
        )

    def open(self, retries: int = 5, delay: float = 0.5) -> None:
        if not usb_edl:
            raise RuntimeError(f"usb_edl unavailable: {_EDL_IMPORT_ERROR}")
        self.edl = UsbEdl(serial=getattr(self.info, "serial", "") or None)
        # usb_edl wants a longer re-enumeration window; honour the caller's
        # retry count but provide a sane minimum.
        self.edl.open(retries=max(retries, 8), delay=delay)

    def close(self) -> None:
        if self.edl is not None:
            self.edl.close()
            self.edl = None

    def write(self, data: bytes) -> None:
        if self.edl is None:
            raise RuntimeError("USB transport is not open")
        self.edl.write(data, timeout_ms=max(1, int(self.io_timeout * 5000)))

    def read(self, n: int) -> bytes:
        if self.edl is None:
            raise RuntimeError("USB transport is not open")
        return self.edl.read(n, timeout_ms=max(1, int(self.io_timeout * 1000)))


def parse_packet_header(raw: bytes) -> Tuple[int, int]:
    if len(raw) < 8:
        raise ValueError("short Sahara header")
    cmd, length = struct.unpack_from("<II", raw, 0)
    if length < 8 or length > 0x100000:
        raise ValueError(f"implausible Sahara length {length:#x} cmd={cmd:#x}")
    return cmd, length


def read_variable_packet(port: ByteTransport, timeout: float = 2.0) -> bytes:
    head = port.read_exact(8, timeout)
    if len(head) != 8:
        raise TimeoutError(f"zero response header: got {len(head)} B")
    cmd, length = parse_packet_header(head)
    rest = port.read_exact(length - 8, timeout)
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


def build_steps(res: Resources, zero_len: int = ZERO_PBLEXP,
                reset_count: int = 175) -> List[HostStep]:
    if zero_len not in ZERO_CHOICES:
        raise ValueError(f"zero_len must be one of {ZERO_CHOICES}")
    if zero_len > len(res.zero_segment):
        raise ValueError("zero_len exceeds the zero resource")
    zero = res.zero_segment[:zero_len]
    if any(zero):
        raise ValueError("zero segment is not all zero")
    return [
        HostStep("hello710", HELLO710, 0x20,
                 "READ_DATA64 image=0xd offset=0x0 size=0x40"),
        HostStep("elf_header", res.elf_header, 0x20,
                 "READ_DATA64 image=0xd offset=0x40 size=0x4d0"),
        HostStep("program_headers", res.program_headers, 0x20,
                 "READ_DATA64 image=0xd offset=0x1000 size=0x1000"),
        HostStep("segment1", res.segment1, 0x20,
                 "READ_DATA64 image=0xd offset=0x2000 size=0xbe8"),
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
               read_timeout: float = 3.0, strict: bool = True) -> None:
    for idx, step in enumerate(steps):
        # The reset step is 175 independent one-byte writes, each followed by
        # a HELLO read.  Do not coalesce them into one write.
        if step.name == "reset_state_machine":
            for i in range(step.repeat):
                try:
                    port.write(step.data)
                except Exception as exc:
                    raise RuntimeError(
                        f"TX reset {i + 1}/{step.repeat} failed: {exc}. "
                        "The PBL may have dropped USB; power-cycle before "
                        "retrying."
                    ) from exc
                try:
                    raw = port.read_exact(0x30, read_timeout)
                except Exception as exc:
                    raise RuntimeError(
                        f"RX reset {i + 1}/{step.repeat} failed: {exc}"
                    ) from exc
                if len(raw) != 0x30:
                    raise RuntimeError(
                        f"reset {i + 1}/{step.repeat}: got {len(raw)}/0x30 B"
                    )
                cmd, length = struct.unpack_from("<II", raw, 0)
                if cmd != 0x01:
                    msg = (f"reset {i + 1}/{step.repeat}: expected HELLO, "
                           f"got {SAHARA_NAMES.get(cmd, hex(cmd))}")
                    if strict:
                        raise RuntimeError(msg)
                    log(f"       WARN {msg}")
                if (i + 1) % 25 == 0 or i + 1 == step.repeat:
                    log(f"       reset {i + 1}/{step.repeat}")
            continue

        data = step.data * step.repeat
        try:
            port.write(data)
        except Exception as exc:
            raise RuntimeError(
                f"TX {step.name} failed: {exc}.  The PBL may have dropped USB; "
                "power-cycle before retrying."
            ) from exc
        log(f"[{idx:02d}] TX {step.name:24s} {len(data):#7x} B")
        if step.read_len == 0:
            continue
        if step.name == "zero_segment":
            try:
                pkt = read_variable_packet(port, read_timeout)
                cmd, length = parse_packet_header(pkt)
                if cmd == 0x04 and length >= 0x10:
                    image, status = struct.unpack_from("<II", pkt, 8)
                    log(f"       RX END_IMAGE_TX image={image:#x} status={status:#x}")
                elif cmd == 0x01:
                    log(f"       RX HELLO {length:#x} B (entry/reset, not a "
                        f"success ack)")
                else:
                    log(f"       RX {SAHARA_NAMES.get(cmd, hex(cmd))} {length:#x} B")
                port.drain(0.2)
            except Exception as exc:
                msg = f"zero response read failed: {exc}"
                if strict:
                    raise RuntimeError(msg) from exc
                log(f"       WARN {msg}")
            continue
        try:
            raw = port.read_exact(step.read_len, read_timeout)
        except Exception as exc:
            raise RuntimeError(
                f"RX {step.name} failed: {exc}.  Check the PBL state; a power "
                "cycle may be required."
            ) from exc
        if len(raw) != step.read_len:
            msg = f"RX {step.name}: got {len(raw)}/{step.read_len} B"
            if strict:
                raise RuntimeError(msg)
            log(f"       WARN {msg}")
            continue
        cmd, length = struct.unpack_from("<II", raw, 0)
        name = SAHARA_NAMES.get(cmd, f"CMD_{cmd:#x}")
        detail = ""
        if cmd == 0x12 and length >= 0x20:
            image, off, size = struct.unpack_from("<QQQ", raw, 8)
            detail = f" image={image:#x} offset={off:#x} size={size:#x}"
        log(f"       RX {name} {length:#x} B{detail}")
        if step.name == "reset_state_machine" and cmd != 0x01:
            msg = f"reset {idx} returned {name}, not HELLO"
            if strict:
                raise RuntimeError(msg)
            log(f"       WARN {msg}")
    log("HOST SEQUENCE COMPLETE")


def run_host(args: argparse.Namespace, res: Resources) -> int:
    steps = build_steps(res, args.zero_len, args.reset_count)
    print_steps(steps)
    if args.dry_run:
        return 0
    port = open_transport(args)
    try:
        send_steps(port, steps, args.read_timeout, not args.relaxed)
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
    firehose: bytes = b""
    opened_transport: str = ""


def try_parse(buf: bytearray) -> Optional[Tuple[int, int, bytes]]:
    if len(buf) < 8:
        return None
    cmd, length = struct.unpack_from("<II", buf, 0)
    if length < 8 or length > 0x100000:
        del buf[0]
        return None
    if len(buf) < length:
        return None
    raw = bytes(buf[:length])
    del buf[:length]
    return cmd, length, raw


def decode_read(raw: bytes) -> Tuple[int, int, int]:
    cmd, length = struct.unpack_from("<II", raw, 0)
    if cmd == 0x12 and length >= 0x20:
        image, off, size = struct.unpack_from("<QQQ", raw, 8)
        return image, off, size
    if cmd == 0x03 and length >= 0x14:
        image, off, size = struct.unpack_from("<III", raw, 8)
        return image, off, size
    raise ValueError(f"not a READ_DATA packet: cmd={cmd:#x} len={length:#x}")


def serve_chunk(image: bytes, off: int, size: int) -> bytes:
    if off < 0 or size < 0:
        return b""
    if off >= len(image):
        return b"\0" * size
    chunk = image[off:off + size]
    if len(chunk) < size:
        chunk += b"\0" * (size - len(chunk))
    return chunk


def run_serve(args: argparse.Namespace, image_path: str) -> int:
    image = read_file(image_path)
    log(f"image: {image_path} ({len(image):#x} B) sha256={sha256(image)}")
    if args.dry_run:
        log(f"port: {args.port} (not opened)")
        log(f"loader HELLO_RESP: {len(LOADER_HELLO):#x} B; "
            f"xml={args.xml}")
        log(f"expect {sum(1 for _ in image):#x} image bytes served")
        return 0
    port = open_transport(args)
    result = ServeResult(opened_transport=port.description)
    buf = bytearray()
    deadline = time.monotonic() + args.total_timeout
    sent_hello = not args.no_hello
    done_deadline = 0.0
    try:
        port.open(args.open_retries, args.open_retry_delay)
        if sent_hello:
            port.write(LOADER_HELLO)
            log(f"TX loader HELLO_RESP: {len(LOADER_HELLO):#x} B")
        while time.monotonic() < deadline:
            try:
                chunk = port.read(0x10000)
            except PermissionError as exc:
                log(f"RX PermissionError (USB transition): {exc}")
                if result.end_image_tx and result.end_image_tx[1] == 0:
                    break
                if result.read_requests == 0 and not args.no_reopen:
                    log("reopening after USB re-enumeration")
                    port.close()
                    time.sleep(args.handoff_delay)
                    try:
                        port = open_transport(args)
                        result.opened_transport = port.description
                        if sent_hello:
                            port.write(LOADER_HELLO)
                        continue
                    except Exception as re_exc:
                        log(f"reopen failed: {re_exc}")
                        break
                break
            except Exception as exc:
                log(f"RX error: {exc}")
                break
            if chunk:
                buf += chunk
                while True:
                    pkt = try_parse(buf)
                    if pkt is None:
                        break
                    cmd, length, raw = pkt
                    name = SAHARA_NAMES.get(cmd, f"CMD_{cmd:#x}")
                    if cmd == 0x01:
                        log(f"RX HELLO {length:#x} B; sending HELLO_RESP")
                        port.write(LOADER_HELLO)
                        sent_hello = True
                        continue
                    if cmd in (0x12, 0x03):
                        image_id, off, size = decode_read(raw)
                        data = serve_chunk(image, off, size)
                        result.read_requests += 1
                        result.bytes_served += len(data)
                        if result.read_requests <= 8 or result.read_requests % 32 == 0:
                            log(f"RX {name} image={image_id} off={off:#x} "
                                f"size={size:#x} served={len(data):#x} "
                                f"total={result.bytes_served:#x}")
                        port.write(data)
                        continue
                    if cmd == 0x04:
                        image_id, status = struct.unpack_from("<II", raw, 8)
                        result.end_image_tx = (image_id, status)
                        log(f"RX END_IMAGE_TX image={image_id:#x} status={status:#x}")
                        if status == 0:
                            port.write(DONE)
                            log(f"TX DONE: {len(DONE):#x} B")
                            done_deadline = time.monotonic() + 2.0
                        else:
                            # A non-zero END_IMAGE_TX is terminal; do not wait
                            # for the full 90 s loader window.
                            break
                        continue
                    if cmd == 0x06:
                        result.done_resp = True
                        log(f"RX DONE_RESP {length:#x} B: {hx(raw)}")
                        continue
                    log(f"RX {name} {length:#x} B: {hx(raw)}")
            else:
                if result.end_image_tx and result.end_image_tx[1] == 0:
                    if time.monotonic() >= done_deadline:
                        break
        if result.end_image_tx and result.end_image_tx[1] == 0 and args.xml != "none":
            time.sleep(1.0)
            payload = CONFIGURE_UFS if args.xml == "ufs" else CONFIGURE_EMMC
            try:
                port.write(payload)
                log(f"TX configure XML ({args.xml}): {len(payload)} B")
            except Exception as exc:
                log(f"configure write failed: {exc}")
            end = time.monotonic() + 8.0
            while time.monotonic() < end:
                try:
                    chunk = port.read(0x10000)
                except Exception as exc:
                    log(f"configure read error: {exc}")
                    break
                if chunk:
                    result.firehose += chunk
                    log(f"RX firehose {len(chunk)} B: {hx(chunk, 160)}")
                    if b"<response" in result.firehose:
                        break
    finally:
        port.close()

    log("")
    log("=" * 70)
    log(f"transport:          {result.opened_transport}")
    log(f"READ_DATA requests: {result.read_requests}")
    log(f"bytes served:       {result.bytes_served:#x}")
    log(f"END_IMAGE_TX:       {result.end_image_tx}")
    log(f"DONE_RESP:          {result.done_resp}")
    log(f"firehose response:  {hx(result.firehose, 200) or '-'}")
    if b"<response" in result.firehose:
        log("RESULT: programmer executed and answered Firehose XML")
        return 0
    if result.end_image_tx and result.end_image_tx[1] == 0:
        log("RESULT: programmer image accepted (status 0) but no XML answer")
        return 2
    if result.read_requests:
        log("RESULT: loader requests seen, image not completed")
        return 3
    log("RESULT: no loader/READ_DATA packets (phase did not run or loader not ready)")
    return 3


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------


def run_ping(args: argparse.Namespace) -> int:
    port = open_transport(args)
    payload = CONFIGURE_UFS if args.xml == "ufs" else CONFIGURE_EMMC
    try:
        port.write(payload)
        log(f"TX configure ({args.xml}): {len(payload)} B")
        buf = b""
        end = time.monotonic() + args.timeout
        while time.monotonic() < end:
            try:
                chunk = port.read(0x10000)
            except Exception as exc:
                log(f"RX error: {exc}")
                break
            if chunk:
                buf += chunk
                log(f"RX {len(chunk)} B: {hx(chunk, 200)}")
                if b"<response" in buf:
                    break
    finally:
        port.close()
    if b"<response" in buf:
        log("RESULT: programmer responded")
        return 0
    log("RESULT: no Firehose response")
    return 2


# ---------------------------------------------------------------------------
# All: host + handoff + serve
# ---------------------------------------------------------------------------


def run_all(args: argparse.Namespace, res: Resources, image_path: str) -> int:
    steps = build_steps(res, args.zero_len, args.reset_count)
    print_steps(steps)
    if args.dry_run:
        log(f"handoff: {args.handoff_delay:.2f}s, then serve {image_path}")
        return 0
    port = open_transport(args)
    try:
        send_steps(port, steps, args.read_timeout, not args.relaxed)
    finally:
        port.close()
    log(f"handoff: waiting {args.handoff_delay:.2f}s")
    time.sleep(args.handoff_delay)
    # The PBL may re-enumerate; resolve again rather than trusting the old path.
    return run_serve(args, image_path)


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
        data = read_file(image)
        log(f"  OK    {os.path.basename(image):44s} {len(data):#6x} B  "
            f"{sha256(data)}")
    else:
        log("  (no programmer image found; pass --image for the serve test)")
    return 0


def cmd_dry(args: argparse.Namespace) -> int:
    res = load_resources(args.resources, args.segment1, args.segment1_hash)
    if args.mode == "host":
        print_steps(build_steps(res, args.zero_len, args.reset_count))
        return 0
    if args.mode == "all":
        print_steps(build_steps(res, args.zero_len, args.reset_count))
        image = resolve_image(args.image)
        log(f"handoff: {args.handoff_delay:.2f}s")
        log(f"serve image: {image or '(none found)'}")
        return 0
    if args.mode == "serve":
        image = resolve_image(args.image)
        if not image:
            log("no programmer image found; pass --image")
            return 1
        log(f"serve image: {image}")
        log(f"loader HELLO_RESP: {len(LOADER_HELLO):#x} B")
        log(f"xml: {args.xml}")
        return 0
    if args.mode == "ping":
        log(f"configure XML ({args.xml}): "
            f"{len(CONFIGURE_UFS if args.xml == 'ufs' else CONFIGURE_EMMC)} B")
        return 0
    raise SystemExit(f"unknown dry-run mode {args.mode}")


def self_test() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    res = load_resources(os.path.join(here, "resources"))
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
    # serve padding / range
    img = bytes(range(256)) * 4
    assert serve_chunk(img, 0, 64) == img[:64]
    assert serve_chunk(img, 2000, 16) == b"\0" * 16
    assert serve_chunk(img, 1020, 10) == img[1020:1024] + b"\0" * 6
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


def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--transport", choices=["auto", "serial", "usb"],
                   default="auto",
                   help="auto (USB on macOS, serial elsewhere), serial, or usb")
    p.add_argument("--port", default="auto",
                   help="serial port path or 'auto' (default: auto; ignored "
                        "for --transport usb)")
    p.add_argument("--usb-bus", type=int, default=None,
                   help="optional libusb bus number for USB selection")
    p.add_argument("--usb-address", type=int, default=None,
                   help="optional libusb device address for USB selection")
    p.add_argument("--resources", default=default_resources(),
                   help="resource directory (default: ./resources)")
    p.add_argument("--segment1", default=None,
                   help="override segment1.bin (e.g. a patched payload)")
    p.add_argument("--segment1-hash", default=None,
                   help="expected SHA-256 for the segment1 resource/override")
    p.add_argument("--io-timeout", type=float, default=0.2,
                   help="serial read timeout in seconds")
    p.add_argument("--port-timeout", type=float, default=8.0,
                   help="seconds to wait for auto-detection")
    p.add_argument("--reopen-timeout", type=float, default=10.0,
                   help="seconds to wait for re-enumeration")
    p.add_argument("--open-retries", type=int, default=5)
    p.add_argument("--open-retry-delay", type=float, default=0.5)
    p.add_argument("--handoff-delay", type=float, default=1.0,
                   help="delay after segment3 before handoff/serve")
    p.add_argument("--zero-len", type=lambda s: int(s, 0), default=ZERO_PBLEXP,
                   choices=ZERO_CHOICES)
    p.add_argument("--reset-count", type=int, default=175)
    p.add_argument("--read-timeout", type=float, default=3.0)
    p.add_argument("--relaxed", action="store_true",
                   help="log and continue on missing/odd responses")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-reopen", action="store_true",
                   help="serve: do not reopen after a USB transition")
    p.add_argument("--image", default=None,
                   help="programmer image path (serve/all)")
    p.add_argument("--xml", choices=["ufs", "emmc", "none"], default="ufs")
    p.add_argument("--no-hello", action="store_true",
                   help="serve: do not send loader HELLO_RESP")
    p.add_argument("--total-timeout", type=float, default=90.0)


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
    p_ping.add_argument("--timeout", type=float, default=10.0)

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

    if args.cmd == "self-test":
        return self_test()
    if args.cmd == "list-ports":
        list_ports_report()
        return 0
    if args.cmd == "check-resources":
        return cmd_check(args)
    if args.cmd == "dry-run":
        # dry-run should not require a serial port, but it does require the
        # same resource verification and prints the exact sequence.
        args.port = "auto"
        return cmd_dry(args)

    try:
        if args.cmd == "ping":
            if args.dry_run:
                return cmd_dry(args)
            return run_ping(args)

        res = load_resources(args.resources, args.segment1, args.segment1_hash)
        image = resolve_image(args.image)
        if args.cmd in ("serve", "all") and not image:
            raise SystemExit("no programmer image found; pass --image PATH")
        if args.cmd == "host":
            return run_host(args, res)
        if args.cmd == "serve":
            return run_serve(args, image)  # type: ignore[arg-type]
        if args.cmd == "all":
            return run_all(args, res, image)  # type: ignore[arg-type]
        raise SystemExit(f"unknown command {args.cmd}")
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
