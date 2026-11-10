import contextlib
import io
import unittest
from unittest.mock import patch

import pblexp_macos as p
from usb_edl import EdlInterface
from test_protocol import Clock, args


def info(address=2, ports=(3,), bus=1):
    return EdlInterface(0,129,1,512,512,'','',bus,address,ports,0x9008)


class Edl:
    def __init__(self, **kwargs): self.kwargs=kwargs
    def open(self,**kwargs): return self
    def close(self): pass


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.quiet=contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None,None,None)

    def test_multiple_targets_fail_without_opening(self):
        with patch.object(p,'edl_find_devices',return_value=[(object(),info()),(object(),info(4,(5,)))]), \
             patch.object(p,'UsbEdl') as opening:
            with self.assertRaisesRegex(RuntimeError,'multiple'):
                p.open_transport(args(transport='usb'))
            opening.assert_not_called()

    def test_filters_are_applied_before_descriptor_queries(self):
        requested=[]
        def discover(**filters):
            requested.append(filters)
            if filters.get('bus') != 1 or filters.get('address') != 2:
                raise OSError('unrelated unconfigured device')
            return [(object(),info())]
        with patch.object(p,'edl_find_devices',side_effect=discover):
            kind,selected=p.resolve_endpoint(args(transport='usb',usb_bus=1,usb_address=2))
        self.assertEqual((kind,selected.address),('usb',2))
        self.assertEqual(requested[0]['pid'],0x9008)

    def test_discovery_waits_for_device_and_uses_shared_backend(self):
        clock=Clock()
        with patch.object(p,'edl_find_devices',side_effect=[[],[(object(),info())]]), \
             patch.object(p,'UsbEdl',Edl), \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            a=args(transport='usb',open_retry_delay=.05)
            transport=p.open_transport(a)
        self.assertIsInstance(transport,p.UsbEdlTransport)
        self.assertEqual(a._usb_identity,(1,(3,),2))
        self.assertEqual(clock.now,.05)
        self.assertEqual(transport.edl.kwargs['info'],info())

    def test_absence_is_bounded_by_discovery_timeout(self):
        clock=Clock()
        with patch.object(p,'edl_find_devices',return_value=[]), \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            with self.assertRaises(p.DeviceNotFound):
                p.open_transport(args(transport='usb',port_timeout=.2,open_retry_delay=.05))
        self.assertAlmostEqual(clock.now,.2)

    def test_reopen_uses_new_address_at_same_physical_port(self):
        a=args(transport='usb',usb_bus=1,usb_address=2)
        a._usb_identity=(1,(3,),2)
        with patch.object(p,'edl_find_devices',return_value=[(object(),info(9))]):
            _,selected=p.resolve_endpoint(a)
        self.assertEqual(selected.address,9)

    def test_reopen_never_selects_other_physical_port(self):
        a=args(transport='usb');a._usb_identity=(1,(3,),2)
        with patch.object(p,'edl_find_devices',return_value=[(object(),info(9,(4,)))]):
            with self.assertRaises(p.DeviceNotFound):p.resolve_endpoint(a)

    def test_no_port_path_does_not_select_a_new_usb_address(self):
        a=args(transport='usb');a._usb_identity=(1,(),2)
        with patch.object(p,'edl_find_devices',return_value=[(object(),info(9,()))]):
            with self.assertRaises(p.DeviceNotFound):p.resolve_endpoint(a)

    def test_explicit_usb_selector_never_falls_back_to_serial(self):
        with patch.object(p.sys,'platform','linux'), patch.object(p,'find_9008_port',return_value='/dev/ttyUSB0'), \
             patch.object(p,'edl_find_devices',return_value=[(object(),info())]):
            kind,_=p.resolve_endpoint(args(usb_bus=1,usb_address=2))
        self.assertEqual(kind,'usb')

    def test_transient_discovery_disconnect_retries(self):
        clock=Clock()
        with patch.object(p,'edl_find_devices',side_effect=[OSError(19,'transition'),[(object(),info())]]), \
             patch.object(p,'UsbEdl',Edl), \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            transport=p.open_transport(args(transport='usb',open_retry_delay=.05))
        self.assertIsInstance(transport,p.UsbEdlTransport)
        self.assertEqual(clock.now,.05)

    def test_permission_failure_during_discovery_is_not_retried(self):
        clock=Clock()
        with patch.object(p,'edl_find_devices',side_effect=PermissionError(13,'denied')), \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            with self.assertRaises(PermissionError):p.open_transport(args(transport='usb'))
        self.assertEqual(clock.now,0)


if __name__=='__main__':unittest.main()
