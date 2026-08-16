import importlib.util
import socket
import struct
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "orbstack-sonos-relay.py"
SPEC = importlib.util.spec_from_file_location("orbstack_sonos_relay", MODULE_PATH)
assert SPEC and SPEC.loader
relay = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = relay
SPEC.loader.exec_module(relay)


def ethernet_udp_packet(
    payload: bytes,
    *,
    source_ip: str = "192.168.139.2",
    destination_ip: str = relay.SSDP_MULTICAST,
    source_port: int = 49152,
    destination_port: int = relay.SSDP_PORT,
    protocol: int = socket.IPPROTO_UDP,
) -> bytes:
    udp_length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + payload
    total_length = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    return ethernet + ip + udp


MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b"MAN: \"ssdp:discover\"\r\n"
    b"MX: 3\r\n"
    b"ST:ssdp:all\r\n\r\n"
)


class PortParsingTests(unittest.TestCase):
    def test_single_ranges_and_duplicates(self):
        self.assertEqual(relay.parse_ports("1400-1402,1401,1450"), [1400, 1401, 1402, 1450])

    def test_invalid_ranges_and_ports(self):
        for value in ("", "1401-1400", "zero", "0", "65536"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                relay.parse_ports(value)


class SSDPTests(unittest.TestCase):
    def test_header_parsing_is_case_insensitive(self):
        headers = relay.parse_ssdp_headers(MSEARCH)
        self.assertEqual(headers["host"], "239.255.255.250:1900")
        self.assertEqual(headers["st"], "ssdp:all")
        self.assertEqual(headers["mx"], "3")

    def test_sonos_response_classification(self):
        for marker in (b"USN: uuid:RINCON_123", b"SERVER: Linux UPnP/1.0 Sonos/80.1",
                       b"LOCATION: http://speaker:1400/xml/device_description.xml\r\nZonePlayer"):
            with self.subTest(marker=marker):
                self.assertTrue(relay.looks_like_sonos_response(b"HTTP/1.1 200 OK\r\n" + marker + b"\r\n\r\n"))
        self.assertFalse(relay.looks_like_sonos_response(b"HTTP/1.1 200 OK\r\nSERVER: Other\r\n\r\n"))
        self.assertFalse(relay.looks_like_sonos_response(b"NOTIFY * HTTP/1.1\r\nUSN: RINCON_1\r\n"))

    def test_parses_multicast_and_broadcast_msearch(self):
        for destination in (relay.SSDP_MULTICAST, relay.SSDP_BROADCAST):
            with self.subTest(destination=destination):
                parsed = relay.parse_msearch_packet(ethernet_udp_packet(MSEARCH, destination_ip=destination))
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.source_ip, "192.168.139.2")
                self.assertEqual(parsed.source_port, 49152)
                self.assertEqual(parsed.destination_ip, destination)
                self.assertEqual(parsed.payload, MSEARCH)

    def test_rejects_non_msearch(self):
        self.assertIsNone(relay.parse_msearch_packet(ethernet_udp_packet(b"NOTIFY * HTTP/1.1\r\n\r\n")))

    def test_rejects_non_1900_destination_port(self):
        packet = ethernet_udp_packet(MSEARCH, destination_port=1901)
        self.assertIsNone(relay.parse_msearch_packet(packet))

    def test_rejects_other_destination_and_non_udp(self):
        self.assertIsNone(relay.parse_msearch_packet(
            ethernet_udp_packet(MSEARCH, destination_ip="192.168.139.255")
        ))
        self.assertIsNone(relay.parse_msearch_packet(
            ethernet_udp_packet(MSEARCH, protocol=socket.IPPROTO_TCP)
        ))

    def test_rejects_truncated_packet(self):
        self.assertIsNone(relay.parse_msearch_packet(ethernet_udp_packet(MSEARCH)[:-4]))


class DeduplicationTests(unittest.TestCase):
    def test_duplicate_is_suppressed_only_inside_window(self):
        dedupe = relay.SearchDeduplicator(window=1.0)
        client = ("192.168.139.2", 49152)
        self.assertTrue(dedupe.accept(client, MSEARCH, now=10.0))
        self.assertFalse(dedupe.accept(client, MSEARCH, now=10.5))
        self.assertTrue(dedupe.accept(client, MSEARCH, now=11.0))

    def test_different_source_port_or_payload_is_distinct(self):
        dedupe = relay.SearchDeduplicator()
        self.assertTrue(dedupe.accept(("192.168.139.2", 49152), MSEARCH, now=1.0))
        self.assertTrue(dedupe.accept(("192.168.139.2", 49153), MSEARCH, now=1.1))
        self.assertTrue(dedupe.accept(("192.168.139.2", 49152), MSEARCH + b" ", now=1.2))


class BackendStateTests(unittest.TestCase):
    def test_auto_mode_pins_first_address(self):
        backend = relay.BackendState(None)
        self.assertTrue(backend.observe("192.168.139.2"))
        self.assertFalse(backend.observe("192.168.139.9"))
        self.assertEqual(backend.get(), "192.168.139.2")


if __name__ == "__main__":
    unittest.main()
