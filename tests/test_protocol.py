import argparse
import contextlib
import io
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pblexp_macos as p


def read64(off=0, size=3, image=13):
    return struct.pack('<IIQQQ', 18, 32, image, off, size)


def eoi(status=0, image=13):
    return struct.pack('<IIII', 4, 16, image, status)


def done(status=1):
    return struct.pack('<III', 6, 12, status)


class Clock:
    now = 0.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


class Transport(p.ByteTransport):
    description = 'fake serial'
    def __init__(self, packets=(), clock=None):
        self.packets = list(packets)
        self.clock = clock or Clock()
        self.opens = 1  # factory contract: already open
        self.closes = 0
        self.reads = 0
        self.writes = []
    def open(self, *args): self.opens += 1
    def close(self): self.closes += 1
    def write(self, data): self.writes.append(bytes(data))
    def read(self, n):
        self.reads += 1
        self.clock.now += .05
        if not self.packets: return b''
        packet = self.packets.pop(0)
        if isinstance(packet, Exception): raise packet
        if len(packet) > n:
            self.packets.insert(0, packet[n:])
        return packet[:n]
    def drain(self, seconds=.2): return b''


def args(**updates):
    parser = argparse.ArgumentParser()
    p.add_common(parser)
    result = parser.parse_args([])
    result.total_timeout = .3
    result.xml = 'none'
    result.handoff_delay = 0
    result.no_hello = False
    result.__dict__.update(updates)
    return result


def resources():
    return p.Resources('/synthetic', b'H'*64, b'P'*1232, b'A'*4096,
                       b'B'*1008, b'C'*936, bytes(3064))


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.image = os.path.join(self.tmp.name, 'programmer')
        with open(self.image, 'wb') as f: f.write(b'abc')

    def serve(self, packets, **updates):
        clock = Clock()
        port = Transport(packets, clock)
        with patch.object(p, 'open_transport', return_value=port), \
             patch.object(p.time, 'monotonic', clock.monotonic), \
             patch.object(p.time, 'sleep', clock.sleep):
            result = p.run_serve(args(**updates), self.image)
        return result, port

    def test_complete_sahara_without_xml_succeeds_and_opens_once(self):
        result, port = self.serve([read64(), eoi(), done()])
        self.assertEqual(result, 0)
        self.assertEqual(port.opens, 1)
        self.assertEqual(port.closes, 1)
        self.assertIn(b'abc', port.writes)

    def test_rejection_stops_without_another_read(self):
        result, port = self.serve([eoi(1)])
        self.assertEqual(result, 3)
        self.assertEqual(port.reads, 1)
        self.assertNotIn(p.DONE, port.writes)

    def test_pending_done_is_not_complete_and_does_not_ping(self):
        result, port = self.serve([read64(), eoi(), done(0)], xml='ufs')
        self.assertEqual(result, 2)
        self.assertNotIn(p.CONFIGURE_UFS, port.writes)

    def test_unknown_image_never_gets_programmer_data(self):
        with self.assertRaises(ValueError): self.serve([read64(image=99)])

    def test_end_image_must_match_programmer_id(self):
        with self.assertRaises(ValueError): self.serve([eoi(image=99)])

    def test_done_before_end_image_is_rejected(self):
        with self.assertRaises(ValueError): self.serve([done()])

    def test_incomplete_sahara_cannot_report_success_from_xml(self):
        with self.assertRaises(ValueError): self.serve([read64(), b'<response value="ACK"/>'])

    def test_strict_host_rejects_wrong_command_before_next_payload(self):
        port = Transport([struct.pack('<II', 8, 8)])
        with self.assertRaises((ValueError, RuntimeError)):
            p.send_steps(port, p.build_steps(resources()), .1, strict=True)
        self.assertEqual(port.writes, [p.HELLO710])

    def test_strict_host_rejects_wrong_read_range(self):
        port = Transport([read64(off=1, size=64)])
        with self.assertRaises((ValueError, RuntimeError)):
            p.send_steps(port, p.build_steps(resources()), .1, strict=True)
        self.assertEqual(port.writes, [p.HELLO710])

    def test_host_pairs_each_reset_with_hello(self):
        hello = struct.pack('<IIIIII',1,48,2,2,1024,0) + bytes(24)
        replies = [read64(0,64), read64(64,1232), read64(4096,4096),
                   read64(8192,3048), eoi(8)] + [hello]*3
        port = Transport(replies)
        p.send_steps(port, p.build_steps(resources(), reset_count=3), .1)
        self.assertEqual(port.writes[-5:], [b'\x13']*3 + [b'B'*1008,b'C'*936])

    def test_bad_ranges_fail_before_allocating(self):
        for off,size in [(4,1), (2,2), (0,2**64-1), (0,0),(-1,1)]:
            with self.subTest(off=off,size=size), self.assertRaises(ValueError):
                p.serve_chunk(b'abc',off,size)

    def test_malformed_header_fails_without_resync_stall(self):
        with self.assertRaises(ValueError): p.try_parse(bytearray(struct.pack('<II',4,7)))

    def test_known_command_requires_exact_packet_length(self):
        with self.assertRaises(ValueError): p.try_parse(bytearray(struct.pack('<II',4,8)))

    def test_fragmented_packet_waits_and_coalesced_packet_retains_tail(self):
        buf = bytearray(read64()[:10])
        self.assertIsNone(p.try_parse(buf))
        buf.extend(read64()[10:] + eoi())
        self.assertEqual(p.try_parse(buf)[0], 18)
        self.assertEqual(p.try_parse(buf)[0], 4)
        self.assertEqual(buf, b'')

    def test_invalid_programmer_is_rejected_before_host_open(self):
        with patch.object(p,'open_transport') as opening:
            with self.assertRaises((ValueError,OSError)):
                p.run_all(args(), resources(), self.image+'.missing')
            opening.assert_not_called()

    def test_empty_programmer_is_rejected_before_host_open(self):
        with open(self.image,'wb'): pass
        with patch.object(p,'open_transport') as opening:
            with self.assertRaises(ValueError): p.run_all(args(), resources(), self.image)
            opening.assert_not_called()

    def test_ping_dry_run_needs_no_resources(self):
        self.assertEqual(p.main(['ping','--dry-run','--resources','/missing']),0)
        self.assertEqual(p.main(['dry-run','--mode','ping','--resources','/missing']),0)

    def test_invalid_numeric_flags_are_rejected_before_io(self):
        for flag,value in [('--reset-count','0'),('--read-timeout','-1'),
                           ('--io-timeout','nan'),('--handoff-delay','-1'),
                           ('--open-retries','0'),('--total-timeout','inf'),
                           ('--usb-bus','-1'),('--usb-address','0'),('--usb-address','128')]:
            with self.subTest(flag=flag), patch.object(p,'open_transport') as opening:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    p.main(['host',flag,value])
                opening.assert_not_called()

    def test_ping_none_is_invalid_even_when_dry_running(self):
        for command in (['ping','--dry-run','--xml','none'],
                        ['dry-run','--mode','ping','--xml','none']):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):p.main(command)

    def test_qualcomm_without_edl_identity_is_not_serial_candidate(self):
        self.assertFalse(p._is_9008_text('Qualcomm Diagnostics USB VID:PID=05c6:9001'))

    def test_disconnect_during_initial_hello_reopens_before_serving(self):
        clock=Clock()
        first=Transport(clock=clock)
        def fail_write(data):raise OSError(19,'gone')
        first.write=fail_write
        second=Transport([read64(),eoi(),done()],clock)
        with patch.object(p,'open_transport',side_effect=[first,second]) as opening, \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            result=p.run_serve(args(),self.image)
        self.assertEqual(result,0)
        self.assertEqual(first.closes,1)
        self.assertEqual(second.closes,1)
        self.assertEqual(opening.call_count,2)

    def test_configure_reopens_after_completed_sahara_disconnect(self):
        clock=Clock()
        first=Transport([read64(),eoi(),done()],clock)
        write=first.write
        def changing_write(data):
            if data==p.CONFIGURE_UFS:raise OSError(19,'Firehose transition')
            write(data)
        first.write=changing_write
        second=Transport([b'<data><response value="NAK"/></data>'],clock)
        with patch.object(p,'open_transport',side_effect=[first,second]), \
             patch.object(p.time,'monotonic',clock.monotonic),patch.object(p.time,'sleep',clock.sleep):
            result=p.run_serve(args(xml='ufs'),self.image)
        self.assertEqual(result,0)
        self.assertEqual(second.writes,[p.CONFIGURE_UFS])
        self.assertEqual((first.closes,second.closes),(1,1))


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None,None,None)
        self.specs = {}
        for name,size in [('oppo710_elf_header.bin',64),('oppo710_program_headers.bin',1232),
                          ('segment1.bin',4096),('segment2.bin',1008),('segment3.bin',936),
                          ('common_zero_segment.bin',3064)]:
            data = bytes(size)
            self.specs[name] = (size,p.sha256(data))
            if name != 'common_zero_segment.bin':
                with open(os.path.join(self.tmp.name,name),'wb') as f:f.write(data)

    def test_missing_zero_is_generated_and_verified(self):
        with patch.object(p,'RESOURCE_SPECS',self.specs):
            self.assertEqual(p.load_resources(self.tmp.name).zero_segment,bytes(3064))

    def test_override_requires_explicit_hash(self):
        override = os.path.join(self.tmp.name,'segment1.bin')
        with patch.object(p,'RESOURCE_SPECS',self.specs), self.assertRaises((ValueError,SystemExit)):
            p.load_resources(self.tmp.name,override)

    def test_custom_hash_is_checked(self):
        override = os.path.join(self.tmp.name,'segment1.bin')
        with patch.object(p,'RESOURCE_SPECS',self.specs):
            self.assertEqual(len(p.load_resources(self.tmp.name,override,p.sha256(bytes(4096))).segment1),4096)
            with self.assertRaises((ValueError,SystemExit)):
                p.load_resources(self.tmp.name,override,'f'*64)


if __name__ == '__main__': unittest.main()
