#!/usr/bin/env python3
"""Native macOS/Linux libusb transport for Qualcomm EDL (9008).

macOS does not create a /dev/cu.usbmodem* node for QDLoader 9008: the
interface is vendor-specific (0xFF/0xFF/0xFF or 0x10/0x11/0x13) with two bulk
endpoints.  pyusb/libusb talks to IOKit directly; no kext and no root needed.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Iterable, Optional

try:
    import usb.core
    import usb.util
except Exception as exc:  # pragma: no cover
    usb = None
    _USB_ERR = exc
else:
    _USB_ERR = None

VID = 0x05C6
PIDS = (0x9008, 0x900E, 0x901D)
CLASS = 0xFF
SUBCLASS = 0xFF
PROTOCOLS = (0xFF, 0x10, 0x11, 0x13)


@dataclass
class EdlInterface:
    interface: int
    in_ep: int
    out_ep: int
    in_maxpacket: int
    out_maxpacket: int
    serial: str
    product: str


def _string(dev, index: int) -> str:
    if not index:
        return ""
    try:
        return usb.util.get_string(dev, index) or ""
    except Exception:
        return ""


def find_devices(read_strings: bool = False) -> list[tuple[object, EdlInterface]]:
    """Return (pyusb device, matching interface) pairs, without claiming."""
    if usb is None:
        raise RuntimeError(f"pyusb unavailable: {_USB_ERR}")
    found = []
    for dev in usb.core.find(find_all=True, idVendor=VID):
        # pyusb Device objects expose these attributes directly; Device has no
        # .describe() method.  Previously this raised and skipped every device.
        try:
            id_product = dev.idProduct
            i_serial = dev.iSerialNumber
            i_product = dev.iProduct
        except Exception:
            continue
        if id_product not in PIDS:
            # qdl matches vendor only; keep vendor-specific 05c6 devices too.
            pass
        # Reading string descriptors is a control transfer on this PBL's
        # minimal USB stack; qdl documents that it can wedge/degrade the
        # device.  Only read them when the caller explicitly asks.
        serial = _string(dev, i_serial) if read_strings else ""
        product = _string(dev, i_product) if read_strings else ""
        for cfg in dev:
            for intf in cfg:
                if (intf.bInterfaceClass == CLASS and
                        intf.bInterfaceSubClass == SUBCLASS and
                        intf.bInterfaceProtocol in PROTOCOLS):
                    in_ep = out_ep = None
                    in_mps = out_mps = 0
                    for ep in intf:
                        if (ep.bmAttributes & 0x3) != 0x2:  # bulk
                            continue
                        if ep.bEndpointAddress & 0x80:
                            in_ep = ep.bEndpointAddress
                            in_mps = ep.wMaxPacketSize
                        else:
                            out_ep = ep.bEndpointAddress
                            out_mps = ep.wMaxPacketSize
                    if in_ep is not None and out_ep is not None:
                        found.append((dev, EdlInterface(
                            intf.bInterfaceNumber, in_ep, out_ep,
                            in_mps, out_mps, serial, product)))
        # Do not return the same device twice.
    return found


def list_devices(read_strings: bool = True) -> list[EdlInterface]:
    return [i for _, i in find_devices(read_strings=read_strings)]


class UsbEdl:
    def __init__(self, serial: Optional[str] = None):
        self.serial = serial
        self.dev = None
        self.intf = None
        self.iface = None

    def open(self, retries: int = 20, delay: float = 0.25) -> "UsbEdl":
        last = None
        for _ in range(retries):
            for dev, info in find_devices():
                if self.serial and info.serial and self.serial.lower() not in info.serial.lower():
                    continue
                try:
                    # Do not call set_configuration(): the PBL is already
                    # configured, and a SET_CONFIGURATION can reset the
                    # endpoint state of its minimal USB stack.  qdl opens and
                    # claims without reconfiguring.
                    try:
                        dev.get_active_configuration()
                    except Exception:
                        dev.set_configuration()
                    usb.util.claim_interface(dev, info.interface)
                    # Give the PBL USB stack a moment after enumeration and
                    # clear any stale halt left by an earlier failed transfer.
                    for ep in (info.out_ep, info.in_ep):
                        try:
                            dev.clear_halt(ep)
                        except Exception:
                            pass
                    # Windows' usbser driver sends the CDC line-coding and
                    # control-line-state class requests when the COM port is
                    # opened.  The PBL's vendor interface is not CDC, but the
                    # Windows driver still emits these; mirror them best-effort.
                    try:
                        line_coding = bytes([0x00, 0xc2, 0x01, 0x00,
                                             0x00, 0x00, 0x08])
                        dev.ctrl_transfer(0x21, 0x20, 0, info.interface,
                                          line_coding, 1000)
                    except Exception as exc:
                        _ = exc
                    try:
                        dev.ctrl_transfer(0x21, 0x22, 0, info.interface,
                                          None, 0, 1000)
                    except Exception as exc:
                        _ = exc
                    time.sleep(0.5)
                    self.dev, self.intf = dev, info
                    self.iface = info.interface
                    return self
                except Exception as exc:
                    last = exc
                    try:
                        usb.util.release_interface(dev, info.interface)
                    except Exception:
                        pass
                    try:
                        usb.util.dispose_resources(dev)
                    except Exception:
                        pass
            time.sleep(delay)
        raise RuntimeError(f"no claimable EDL interface found: {last}")

    def close(self) -> None:
        if self.dev is not None:
            try:
                usb.util.release_interface(self.dev, self.iface)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(self.dev)
            except Exception:
                pass
        self.dev = self.intf = self.iface = None

    def write(self, data: bytes, timeout_ms: int = 5000) -> int:
        if self.dev is None or self.intf is None:
            raise RuntimeError("device not open")
        out = self.intf.out_ep
        dev = self.dev
        total = 0
        # pyusb write() returns count; handle short writes.
        while total < len(data):
            try:
                n = dev.write(out, data[total:], timeout_ms)
            except usb.core.USBTimeoutError:
                # A fresh CLEAR_FEATURE can revive a stalled OUT endpoint
                # after an earlier failed transfer; retry once.
                try:
                    dev.clear_halt(out)
                except Exception:
                    pass
                n = dev.write(out, data[total:], timeout_ms)
            if not n:
                raise RuntimeError("short USB write")
            total += n
        # Qualcomm expects a ZLP when the transfer length is a multiple of
        # wMaxPacketSize (see qdl usb_write()).
        if len(data) and len(data) % self.intf.out_maxpacket == 0:
            try:
                dev.write(out, b"", timeout_ms)
            except Exception:
                pass
        return total

    def read(self, size: int, timeout_ms: int = 5000,
             allow_zlp: bool = True) -> bytes:
        if self.dev is None or self.intf is None:
            raise RuntimeError("device not open")
        end = time.monotonic() + timeout_ms / 1000.0
        buf = bytearray()
        while len(buf) < size:
            remaining = max(1, int((end - time.monotonic()) * 1000))
            try:
                chunk = self.dev.read(self.intf.in_ep, size - len(buf),
                                      remaining)
            except usb.core.USBTimeoutError:
                break
            if not chunk:
                if allow_zlp:
                    continue
                break
            buf += bytes(chunk)
        return bytes(buf)

    def read_exact(self, size: int, timeout_ms: int = 5000) -> bytes:
        data = self.read(size, timeout_ms)
        if len(data) != size:
            raise TimeoutError(f"USB read {len(data):#x}/{size:#x}")
        return data


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="List Qualcomm EDL USB interfaces")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        infos = list_devices()
    except Exception as exc:
        print(f"error: {exc}")
        return 2
    if args.json:
        import json
        print(json.dumps([i.__dict__ for i in infos], indent=2))
    else:
        if not infos:
            print("No Qualcomm EDL (9008) USB interface found.")
        for i in infos:
            print(f"{VID:04x}:{PIDS[0]:04x} if={i.interface} "
                  f"in=0x{i.in_ep:02x} out=0x{i.out_ep:02x} "
                  f"mps={i.in_maxpacket}/{i.out_maxpacket} "
                  f"serial={i.serial!r} product={i.product!r}")
    return 0 if infos else 1


if __name__ == "__main__":
    raise SystemExit(_main())
