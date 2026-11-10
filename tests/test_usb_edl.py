"""Host-only transport tests; no USB enumeration or hardware access."""
import types
import unittest
from unittest.mock import Mock, patch

import usb_edl


class UsbError(Exception):
    pass


class UsbTimeout(UsbError):
    pass


def interface(number=0, protocol=0xFF, bulk=True):
    endpoints = [types.SimpleNamespace(bEndpointAddress=0x81,
                                      bmAttributes=2 if bulk else 3,
                                      wMaxPacketSize=64),
                 types.SimpleNamespace(bEndpointAddress=0x01,
                                      bmAttributes=2, wMaxPacketSize=64)]
    class Interface(list):
        bInterfaceNumber = number
        bInterfaceClass = 0xFF
        bInterfaceSubClass = 0xFF
        bInterfaceProtocol = protocol
    return Interface(endpoints)


class Device:
    idVendor = 0x05C6
    idProduct = 0x9008
    iSerialNumber = 1
    iProduct = 2
    bus = 1
    address = 2
    port_numbers = (3, 4)

    def __init__(self, packets=()):
        self.config = [interface()]
        self.packets = list(packets)
        self.reads = []
        self.writes = []
        self.controls = []
        self.driver = False
        self.detached = self.attached = 0
        self.configuration_calls = 0
        self.write_results = []

    def __iter__(self):
        return iter([self.config, [interface(9)]])

    def get_active_configuration(self):
        return self.config

    def set_configuration(self):
        self.configuration_calls += 1

    def is_kernel_driver_active(self, number):
        return self.driver

    def detach_kernel_driver(self, number):
        self.detached += 1

    def attach_kernel_driver(self, number):
        self.attached += 1

    def clear_halt(self, endpoint):
        pass

    def ctrl_transfer(self, bmRequestType, bRequest, wValue=0, wIndex=0,
                      data_or_wLength=None, timeout=None):
        self.controls.append((bmRequestType, bRequest, wValue, wIndex,
                              data_or_wLength, timeout))
        return len(data_or_wLength or b"")

    def read(self, endpoint, size, timeout):
        self.reads.append((endpoint, size, timeout))
        if not self.packets:
            raise UsbTimeout("no data")
        packet = self.packets.pop(0)
        if isinstance(packet, Exception):
            raise packet
        if len(packet) > size:
            raise UsbError("bulk packet overflow")
        return packet

    def write(self, endpoint, data, timeout):
        self.writes.append((endpoint, bytes(data), timeout))
        value = self.write_results.pop(0) if self.write_results else len(data)
        if isinstance(value, Exception):
            raise value
        return value


class UsbTests(unittest.TestCase):
    def setUp(self):
        self.devices = []
        self.claim = Mock()
        self.release = Mock()
        self.dispose = Mock()
        self.get_string = Mock(side_effect=lambda dev, idx: "serial" if idx == 1 else "product")
        self.backend = types.SimpleNamespace(
            core=types.SimpleNamespace(find=lambda **kw: self.devices,
                                       USBError=UsbError, USBTimeoutError=UsbTimeout),
            util=types.SimpleNamespace(claim_interface=self.claim,
                                       release_interface=self.release,
                                       dispose_resources=self.dispose,
                                       get_string=self.get_string))
        self.patch = patch.object(usb_edl, "usb", self.backend)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.sleep = patch.object(usb_edl.time, "sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def opened(self, packets=()):
        dev = Device(packets)
        self.devices = [dev]
        transport = usb_edl.UsbEdl().open(retries=1)
        self.addCleanup(transport.close)
        return dev, transport

    def test_packet_receive_retains_surplus_for_header_then_payload(self):
        for size in (16, 48):
            with self.subTest(size=size):
                packet = bytes(range(size))
                dev, transport = self.opened([packet])
                self.assertEqual(transport.read_exact(8), packet[:8])
                self.assertEqual(transport.read_exact(size - 8), packet[8:])
                self.assertEqual(len(dev.reads), 1)
                self.assertEqual(dev.reads[0][1], 64)

    def test_read_some_returns_short_packet_without_waiting_for_more(self):
        dev, transport = self.opened([b"hello"])
        self.assertEqual(transport.read(4096), b"hello")
        self.assertEqual(len(dev.reads), 1)

    def test_receive_buffer_rounds_up_to_maxpacket_multiple(self):
        dev, transport = self.opened([b"x" * 65])
        self.assertEqual(transport.read(65), b"x" * 65)
        self.assertEqual(dev.reads[0][1], 128)

    def test_read_exact_combines_short_reads(self):
        _, transport = self.opened([b"abc", b"defgh"])
        self.assertEqual(transport.read_exact(8), b"abcdefgh")

    def test_repeated_zlp_exits_at_deadline(self):
        dev, transport = self.opened([b""] * 10)
        with patch.object(usb_edl.time, "monotonic", side_effect=[0, 0, .001, .002, .003, .004, .005, .006, .007, .008, .009, .010]):
            self.assertEqual(transport.read(8, timeout_ms=2), b"")
        self.assertLessEqual(len(dev.reads), 2)

    def test_read_exact_trickle_obeys_one_deadline(self):
        dev, transport = self.opened([b"a"] * 10)
        with patch.object(usb_edl.time, "monotonic", side_effect=[0, 0, .001, .002, .003, .004, .005, .006, .007, .008]):
            with self.assertRaises(TimeoutError):
                transport.read_exact(8, timeout_ms=2)
        self.assertLessEqual(len(dev.reads), 2)

    def test_no_default_cdc_requests(self):
        dev, _ = self.opened()
        self.assertEqual(dev.controls, [])

    def test_opt_in_cdc_requests_bind_and_log_both_successes(self):
        dev = Device()
        self.devices = [dev]
        with self.assertLogs("usb_edl", level="INFO") as logs:
            transport = usb_edl.UsbEdl(cdc_requests=True).open(retries=1)
        self.addCleanup(transport.close)
        self.assertEqual([x[1] for x in dev.controls], [0x20, 0x22])
        self.assertEqual(dev.controls[1], (0x21, 0x22, 0, 0, None, 1000))
        self.assertEqual(len(logs.output), 2)

    def test_cdc_failures_are_observable_and_remain_best_effort(self):
        dev = Device()
        dev.ctrl_transfer = Mock(side_effect=UsbError("unsupported"))
        self.devices = [dev]
        with self.assertLogs("usb_edl", level="WARNING") as logs:
            transport = usb_edl.UsbEdl(cdc_requests=True).open(retries=1)
        self.addCleanup(transport.close)
        self.assertEqual(len(logs.output), 2)

    def test_unconfigured_device_is_never_reset(self):
        dev = Device()
        dev.get_active_configuration = Mock(side_effect=UsbError("unconfigured"))
        self.devices = [dev]
        with self.assertRaises(UsbError):
            usb_edl.UsbEdl().open(retries=1)
        self.assertEqual(dev.configuration_calls, 0)

    def test_repeated_open_is_idempotent(self):
        _, transport = self.opened()
        self.assertIs(transport.open(), transport)
        self.assertEqual(self.claim.call_count, 1)

    def test_kernel_driver_is_restored_on_close(self):
        dev = Device()
        dev.driver = True
        self.devices = [dev]
        transport = usb_edl.UsbEdl().open(retries=1)
        self.assertEqual(dev.detached, 1)
        transport.close()
        transport.close()
        self.assertEqual(dev.attached, 1)
        self.assertEqual(self.release.call_count, 1)

    def test_claim_failure_restores_driver_and_preserves_error(self):
        dev = Device()
        dev.driver = True
        self.devices = [dev]
        self.claim.side_effect = PermissionError("access denied")
        with self.assertRaises(PermissionError):
            usb_edl.UsbEdl().open(retries=1)
        self.assertEqual(dev.attached, 1)
        self.assertEqual(self.dispose.call_count, 1)

    def test_unsupported_kernel_driver_api_allows_claim(self):
        dev = Device()
        dev.is_kernel_driver_active = Mock(side_effect=NotImplementedError)
        self.devices = [dev]
        transport = usb_edl.UsbEdl().open(retries=1)
        self.addCleanup(transport.close)
        self.assertEqual(self.claim.call_count, 1)

    def test_aligned_write_reports_zlp_failure(self):
        dev, transport = self.opened()
        dev.write_results = [64, UsbError("zlp failed")]
        with self.assertRaises(UsbError):
            transport.write(b"x" * 64)

    def test_write_timeout_does_not_replay_unknown_partial_transfer(self):
        dev, transport = self.opened()
        dev.write_results = [UsbTimeout("partial transfer possible"), 4]
        with self.assertRaises(UsbTimeout):
            transport.write(b"abcd")
        self.assertEqual(len(dev.writes), 1)

    def test_short_write_sends_only_remaining_bytes(self):
        dev, transport = self.opened()
        dev.write_results = [2, 2]
        self.assertEqual(transport.write(b"abcd"), 4)
        self.assertEqual([x[1] for x in dev.writes], [b"abcd", b"cd"])

    def test_short_write_loop_is_deadline_bounded(self):
        dev, transport = self.opened()
        dev.write_results = [1] * 10
        with patch.object(usb_edl.time, "monotonic", side_effect=[0, 0, .001, .002, .003, .004, .005, .006, .007, .008, .009]):
            with self.assertRaises(TimeoutError):
                transport.write(b"abcdefgh", timeout_ms=2)
        self.assertLessEqual(len(dev.writes), 2)

    def test_discovery_uses_only_active_configuration_and_no_strings(self):
        self.devices = [Device()]
        result = usb_edl.find_devices()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1].interface, 0)
        self.get_string.assert_not_called()

    def test_discovery_filters_physical_identity_and_product(self):
        self.devices = [Device()]
        self.assertEqual(len(usb_edl.find_devices(bus=1, address=2, pid=0x9008, port_numbers=(3, 4))), 1)
        for filters in ({"bus": 9}, {"address": 9}, {"pid": 0x901D}, {"port_numbers": (5,)}):
            with self.subTest(filters=filters):
                self.assertEqual(usb_edl.find_devices(**filters), [])
        info = usb_edl.find_devices()[0][1]
        self.assertEqual((info.bus, info.address, info.port_numbers, info.product_id), (1, 2, (3, 4), 0x9008))

    def test_discovery_rejects_wrong_interface_and_nonbulk_endpoints(self):
        dev = Device()
        dev.config = [interface(protocol=1), interface(2, bulk=False)]
        self.devices = [dev]
        self.assertEqual(usb_edl.find_devices(), [])

    def test_multiple_devices_require_explicit_selection(self):
        second = Device()
        second.address = 7
        self.devices = [Device(), second]
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            usb_edl.UsbEdl().open(retries=1)
        self.claim.assert_not_called()

    def test_info_selects_discovered_physical_identity(self):
        first, second = Device(), Device()
        second.address = 7
        self.devices = [first, second]
        info = usb_edl.find_devices()[1][1]
        transport = usb_edl.UsbEdl(info=info).open(retries=1)
        self.addCleanup(transport.close)
        self.assertIs(transport.dev, second)

    def test_pinned_open_does_not_inspect_unrelated_unconfigured_device(self):
        selected = Device()
        self.devices = [selected]
        info = usb_edl.find_devices()[0][1]
        unrelated = Device()
        unrelated.address = 7
        unrelated.get_active_configuration = Mock(side_effect=UsbError("unconfigured"))
        self.devices = [unrelated, selected]
        transport = usb_edl.UsbEdl(info=info).open(retries=1)
        self.addCleanup(transport.close)
        self.assertIs(transport.dev, selected)
        unrelated.get_active_configuration.assert_not_called()

    def test_disappeared_pinned_device_does_not_select_another(self):
        self.devices = [Device()]
        info = usb_edl.find_devices()[0][1]
        replacement = Device()
        replacement.address = 7
        self.devices = [replacement]
        with self.assertRaises(RuntimeError):
            usb_edl.UsbEdl(info=info).open(retries=1)
        self.claim.assert_not_called()

    def test_kernel_driver_permission_error_is_not_treated_as_unsupported(self):
        dev = Device()
        dev.is_kernel_driver_active = Mock(side_effect=PermissionError("denied"))
        self.devices = [dev]
        with self.assertRaises(PermissionError):
            usb_edl.UsbEdl().open(retries=1)
        self.claim.assert_not_called()
        self.assertEqual(self.dispose.call_count, 1)

    def test_full_aligned_write_includes_terminating_zlp(self):
        dev, transport = self.opened()
        self.assertEqual(transport.write(b"x" * 64), 64)
        self.assertEqual([call[1] for call in dev.writes], [b"x" * 64, b""])

    def test_supported_vendor_protocols_all_discover(self):
        dev = Device()
        dev.config = [interface(i, protocol) for i, protocol in
                      enumerate((0xFF, 0x10, 0x11, 0x13))]
        self.devices = [dev]
        self.assertEqual([info.interface for _, info in usb_edl.find_devices()], [0, 1, 2, 3])

    def test_requested_serial_never_accepts_unavailable_serial(self):
        self.devices = [Device()]
        self.get_string.side_effect = UsbError("descriptor unavailable")
        with self.assertRaises(RuntimeError):
            usb_edl.UsbEdl(serial="chosen").open(retries=1)
        self.claim.assert_not_called()


if __name__ == "__main__":
    unittest.main()
