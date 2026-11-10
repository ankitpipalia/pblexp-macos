#!/usr/bin/env python3
"""Native macOS/Linux libusb transport for Qualcomm EDL (9008).

macOS does not create a /dev/cu.usbmodem* node for QDLoader 9008: the
interface is vendor-specific (class/subclass 0xFF/0xFF, protocol
0xFF, 0x10, 0x11 or 0x13) with two bulk
endpoints. pyusb/libusb uses the host USB backend directly, subject to the
host's USB access permissions.
"""
from __future__ import annotations
import logging
import math
import time
from dataclasses import dataclass
from typing import Optional

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
_LOG = logging.getLogger(__name__)


@dataclass
class EdlInterface:
    interface: int
    in_ep: int
    out_ep: int
    in_maxpacket: int
    out_maxpacket: int
    serial: str
    product: str
    bus: Optional[int] = None
    address: Optional[int] = None
    port_numbers: tuple[int, ...] = ()
    product_id: Optional[int] = None


def _string(dev, index: int) -> str:
    if not index:
        return ""
    try:
        return usb.util.get_string(dev, index) or ""
    except Exception:
        return ""


def find_devices(read_strings: bool = False, *, bus: Optional[int] = None,
                 address: Optional[int] = None, pid: Optional[int] = None,
                 port_numbers: Optional[tuple[int, ...]] = None
                 ) -> list[tuple[object, EdlInterface]]:
    """Inspect active configurations without claiming or reconfiguring devices.

    Descriptor strings are read only on request. USB errors, including access
    errors and an unconfigured device, are reported to the caller.
    """
    if usb is None:
        raise RuntimeError(f"pyusb unavailable: {_USB_ERR}")
    found = []
    for dev in usb.core.find(find_all=True, idVendor=VID):
        device_ports = tuple(getattr(dev, "port_numbers", None) or ())
        if ((bus is not None and getattr(dev, "bus", None) != bus) or
                (address is not None and getattr(dev, "address", None) != address) or
                (pid is not None and dev.idProduct != pid) or
                (port_numbers is not None and device_ports != tuple(port_numbers))):
            continue
        cfg = dev.get_active_configuration()
        serial = _string(dev, dev.iSerialNumber) if read_strings else ""
        product = _string(dev, dev.iProduct) if read_strings else ""
        for intf in cfg:
            if (intf.bInterfaceClass != CLASS or
                    intf.bInterfaceSubClass != SUBCLASS or
                    intf.bInterfaceProtocol not in PROTOCOLS):
                continue
            in_ep = out_ep = None
            in_mps = out_mps = 0
            for ep in intf:
                if (ep.bmAttributes & 0x3) != 0x2:
                    continue
                if ep.bEndpointAddress & 0x80:
                    in_ep, in_mps = ep.bEndpointAddress, ep.wMaxPacketSize
                else:
                    out_ep, out_mps = ep.bEndpointAddress, ep.wMaxPacketSize
            if in_ep is not None and out_ep is not None and in_mps > 0 and out_mps > 0:
                found.append((dev, EdlInterface(
                    intf.bInterfaceNumber, in_ep, out_ep, in_mps, out_mps,
                    serial, product, getattr(dev, "bus", None),
                    getattr(dev, "address", None), device_ports, dev.idProduct)))
    return found


def list_devices(read_strings: bool = True) -> list[EdlInterface]:
    return [i for _, i in find_devices(read_strings=read_strings)]


class UsbEdl:
    def __init__(self, serial: Optional[str] = None, *,
                 info: Optional[EdlInterface] = None,
                 cdc_requests: bool = False):
        self.serial = serial
        self.info = info
        self.cdc_requests = cdc_requests
        self.dev = None
        self.intf = None
        self.iface = None
        self._detached = False
        self._rx = bytearray()

    def _matches_info(self, candidate: EdlInterface) -> bool:
        if self.info is None:
            return True
        # Bus and address bind this open to the enumerated USB instance. Port
        # paths additionally guard against selecting another physical port.
        if self.info.bus is None or self.info.address is None:
            raise ValueError("selected EDL interface has no bus/address identity")
        attributes = ("bus", "address", "port_numbers", "product_id", "interface",
                      "in_ep", "out_ep", "in_maxpacket", "out_maxpacket")
        return all(getattr(candidate, name) == getattr(self.info, name)
                   for name in attributes)

    def open(self, retries: int = 20, delay: float = 0.25) -> "UsbEdl":
        if self.dev is not None:
            return self
        if retries < 1 or delay < 0:
            raise ValueError("retries must be positive and delay nonnegative")
        filters = {}
        if self.info is not None:
            if self.info.bus is None or self.info.address is None:
                raise ValueError("selected EDL interface has no bus/address identity")
            filters = dict(bus=self.info.bus, address=self.info.address,
                           pid=self.info.product_id,
                           port_numbers=self.info.port_numbers)
        for attempt in range(retries):
            candidates = [(dev, info) for dev, info in
                          find_devices(read_strings=bool(self.serial), **filters)
                          if self._matches_info(info) and
                          (not self.serial or
                           (info.serial and self.serial.casefold() == info.serial.casefold()))]
            if len(candidates) > 1:
                raise RuntimeError("ambiguous EDL interfaces; select a physical device")
            if candidates:
                dev, info = candidates[0]
                claimed = detached = False
                try:
                    # Never use SET_CONFIGURATION as a fallback: it can reset
                    # the target's endpoint/protocol state.
                    dev.get_active_configuration()
                    try:
                        driver_active = dev.is_kernel_driver_active(info.interface)
                    except (NotImplementedError, AttributeError):
                        driver_active = False
                    if driver_active:
                        dev.detach_kernel_driver(info.interface)
                        detached = True
                    usb.util.claim_interface(dev, info.interface)
                    claimed = True
                    if self.cdc_requests:
                        # Experimental compatibility requests. A Windows trace
                        # is needed to establish whether this target uses them.
                        for request, payload in ((0x20, b"\x00\xc2\x01\x00\x00\x00\x08"),
                                                 (0x22, None)):
                            try:
                                result = dev.ctrl_transfer(
                                    bmRequestType=0x21, bRequest=request,
                                    wValue=0, wIndex=info.interface,
                                    data_or_wLength=payload, timeout=1000)
                            except Exception as exc:
                                _LOG.warning("Experimental CDC request %#04x failed: %s", request, exc)
                            else:
                                _LOG.info("Experimental CDC request %#04x completed: %s", request, result)
                    self.dev, self.intf, self.iface = dev, info, info.interface
                    self._detached = detached
                    self._rx.clear()
                    return self
                except Exception:
                    self._cleanup(dev, info.interface, claimed, detached)
                    raise
            if attempt + 1 < retries:
                time.sleep(delay)
        raise RuntimeError("no matching EDL interface found")

    @staticmethod
    def _cleanup(dev, iface, claimed: bool, detached: bool) -> None:
        if claimed:
            try:
                usb.util.release_interface(dev, iface)
            except Exception as exc:
                _LOG.warning("USB interface release failed: %s", exc)
        if detached:
            try:
                dev.attach_kernel_driver(iface)
            except Exception as exc:
                _LOG.warning("USB kernel driver reattach failed: %s", exc)
        try:
            usb.util.dispose_resources(dev)
        except Exception as exc:
            _LOG.warning("USB resource disposal failed: %s", exc)

    def close(self) -> None:
        if self.dev is not None:
            self._cleanup(self.dev, self.iface, True, self._detached)
        self.dev = self.intf = self.iface = None
        self._detached = False
        self._rx.clear()

    @staticmethod
    def _deadline(timeout_ms: int) -> float:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        return time.monotonic() + timeout_ms / 1000.0

    @staticmethod
    def _remaining(deadline: float) -> int:
        remaining = deadline - time.monotonic()
        return max(1, math.ceil(remaining * 1000)) if remaining > 0 else 0

    def write(self, data: bytes, timeout_ms: int = 5000) -> int:
        if self.dev is None or self.intf is None:
            raise RuntimeError("device not open")
        deadline = self._deadline(timeout_ms)
        total = 0
        while total < len(data):
            remaining = self._remaining(deadline)
            if not remaining:
                raise TimeoutError(f"USB write {total:#x}/{len(data):#x}")
            # A timed-out PyUSB write can have transmitted an unknown prefix.
            # Propagate it: replaying the buffer could duplicate wire data.
            n = self.dev.write(self.intf.out_ep, data[total:], remaining)
            if not n or n < 0 or n > len(data) - total:
                raise RuntimeError(f"invalid USB write count: {n}")
            total += n
        if data and len(data) % self.intf.out_maxpacket == 0:
            remaining = self._remaining(deadline)
            if not remaining:
                raise TimeoutError("USB write deadline expired before terminating ZLP")
            n = self.dev.write(self.intf.out_ep, b"", remaining)
            if n != 0:
                raise RuntimeError(f"invalid USB ZLP write count: {n}")
        return total

    def _read_some(self, size: int, deadline: float, allow_zlp: bool) -> bytes:
        if self._rx:
            result = bytes(self._rx[:size])
            del self._rx[:size]
            return result
        packet_size = self.intf.in_maxpacket
        capacity = ((size + packet_size - 1) // packet_size) * packet_size
        while True:
            remaining = self._remaining(deadline)
            if not remaining:
                return b""
            try:
                chunk = bytes(self.dev.read(self.intf.in_ep, capacity, remaining))
            except usb.core.USBTimeoutError:
                return b""
            if chunk:
                self._rx.extend(chunk[size:])
                return chunk[:size]
            if not allow_zlp:
                return b""

    def read(self, size: int, timeout_ms: int = 5000,
             allow_zlp: bool = True) -> bytes:
        """Return up to size bytes promptly after the first nonempty USB read.

        Bulk reads always use maxpacket-multiple buffers. Surplus bytes are
        queued for the next logical read; a short response is returned at once.
        """
        if self.dev is None or self.intf is None:
            raise RuntimeError("device not open")
        if size < 0:
            raise ValueError("size must be nonnegative")
        deadline = self._deadline(timeout_ms)
        return self._read_some(size, deadline, allow_zlp) if size else b""

    def read_exact(self, size: int, timeout_ms: int = 5000) -> bytes:
        if self.dev is None or self.intf is None:
            raise RuntimeError("device not open")
        if size < 0:
            raise ValueError("size must be nonnegative")
        deadline = self._deadline(timeout_ms)
        data = bytearray()
        while len(data) < size:
            chunk = self._read_some(size - len(data), deadline, True)
            if not chunk:
                raise TimeoutError(f"USB read {len(data):#x}/{size:#x}")
            data.extend(chunk)
        return bytes(data)


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
            print(f"{VID:04x}:{i.product_id:04x} bus={i.bus} address={i.address} "
                  f"ports={i.port_numbers} if={i.interface} "
                  f"in=0x{i.in_ep:02x} out=0x{i.out_ep:02x} "
                  f"mps={i.in_maxpacket}/{i.out_maxpacket} "
                  f"serial={i.serial!r} product={i.product!r}")
    return 0 if infos else 1


if __name__ == "__main__":
    raise SystemExit(_main())
