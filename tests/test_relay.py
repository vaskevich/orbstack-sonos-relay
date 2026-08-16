import importlib.util
import ipaddress
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock


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


def ethernet_tcp_packet(
    *,
    source_ip: str = "192.168.139.2",
    destination_ip: str = "192.168.86.21",
    source_port: int = 49152,
    destination_port: int = relay.SONOS_HTTP_PORT,
    data_offset_words: int = 5,
    fragment_field: int = 0,
    vlan_type: int | None = None,
) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        1,
        0,
        data_offset_words << 4,
        0x10,
        65535,
        0,
        0,
    )
    total_length = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        fragment_field,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    if vlan_type is None:
        ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    else:
        ethernet = b"\x00" * 12 + struct.pack("!HHH", vlan_type, 1, 0x0800)
    return ethernet + ip + tcp


MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b"MAN: \"ssdp:discover\"\r\n"
    b"MX: 3\r\n"
    b"ST:ssdp:all\r\n\r\n"
)

ARP_OUTPUT = """\
? (192.168.139.2) at 2:aa:bb:cc:dd:ee on bridge100 ifscope [ethernet]
? (192.168.139.3) at a:bb:cc:dd:ee:ff on bridge100 permanent [bridge]
? (192.168.139.4) at (incomplete) on bridge100 ifscope [ethernet]
? (192.168.139.5) at no entry on bridge100
? (192.168.139.255) at ff:ff:ff:ff:ff:ff on bridge100
? (224.0.0.251) at 1:0:5e:0:0:fb on bridge100 permanent [ethernet]
? (255.255.255.255) at ff:ff:ff:ff:ff:ff on bridge100 permanent [ethernet]
"""


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


class TCPPacketTests(unittest.TestCase):
    def test_parses_ipv4_endpoints_and_destination_1400(self):
        parsed = relay.parse_tcp_packet(ethernet_tcp_packet())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.source_ip, "192.168.139.2")
        self.assertEqual(parsed.source_port, 49152)
        self.assertEqual(parsed.destination_ip, "192.168.86.21")
        self.assertEqual(parsed.destination_port, 1400)

    def test_parses_vlan_wrapped_tcp(self):
        for vlan_type in (0x8100, 0x88A8):
            with self.subTest(vlan_type=vlan_type):
                parsed = relay.parse_tcp_packet(ethernet_tcp_packet(vlan_type=vlan_type))
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.destination_port, 1400)

    def test_rejects_truncated_tcp(self):
        self.assertIsNone(relay.parse_tcp_packet(ethernet_tcp_packet()[:-1]))

    def test_rejects_malformed_tcp_data_offset(self):
        self.assertIsNone(relay.parse_tcp_packet(ethernet_tcp_packet(data_offset_words=4)))

    def test_rejects_fragmented_tcp(self):
        for fragment_field in (0x2000, 0x0001):
            with self.subTest(fragment_field=fragment_field):
                self.assertIsNone(relay.parse_tcp_packet(
                    ethernet_tcp_packet(fragment_field=fragment_field)
                ))

    def test_capture_filter_includes_ssdp_and_sonos_tcp(self):
        self.assertEqual(
            relay.CAPTURE_FILTER,
            "(udp and dst port 1900) or (tcp and dst port 1400)",
        )


class NeighborDiscoveryTests(unittest.TestCase):
    network = ipaddress.ip_network("192.168.139.0/24")

    def test_parses_normal_macos_arp_and_ignores_unusable_entries(self):
        self.assertEqual(
            relay.parse_arp_neighbors(
                ARP_OUTPUT,
                bridge_ip="192.168.139.3",
                bridge_network=self.network,
            ),
            ["192.168.139.2"],
        )

    def test_ignores_bridge_multicast_broadcast_and_incomplete_entries(self):
        text = """\
? (192.168.139.3) at 2:0:0:0:0:3 on bridge100 permanent
? (192.168.139.4) at (incomplete) on bridge100
? (224.0.0.1) at 2:0:0:0:0:1 on bridge100 permanent
? (255.255.255.255) at 2:0:0:0:0:ff on bridge100 permanent
"""
        self.assertEqual(
            relay.parse_arp_neighbors(
                text,
                bridge_ip="192.168.139.3",
                bridge_network=self.network,
            ),
            [],
        )

    def test_one_in_subnet_candidate_accepting_is_selected_and_closed(self):
        probes = []

        class Probe:
            closed = False

            def close(self):
                self.closed = True

        def connector(address, *, timeout):
            probes.append((address, timeout, Probe()))
            return probes[-1][2]

        arp_output = (
            "? (10.0.0.8) at 2:0:0:0:0:8 on bridge100\n"
            "? (192.168.139.2) at 2:0:0:0:0:2 on bridge100\n"
        )
        result = relay.discover_backend_from_neighbors(
            "bridge100",
            "192.168.139.3",
            self.network,
            1400,
            connector=connector,
            runner=lambda *_args, **_kwargs: arp_output,
        )
        self.assertEqual(result.selected, "192.168.139.2")
        self.assertEqual([probe[0] for probe in probes], [("192.168.139.2", 1400)])
        self.assertEqual(probes[0][1], relay.NEIGHBOR_PROBE_TIMEOUT)
        self.assertTrue(probes[0][2].closed)

    def test_zero_candidates_accepting_is_unresolved(self):
        def refused(_address, *, timeout):
            raise ConnectionRefusedError

        result = relay.discover_backend_from_neighbors(
            "bridge100",
            "192.168.139.3",
            self.network,
            1400,
            connector=refused,
            runner=lambda *_args, **_kwargs: ARP_OUTPUT,
        )
        self.assertIsNone(result.selected)
        self.assertFalse(result.ambiguous)
        self.assertEqual(result.accepted, ())

    def test_multiple_candidates_accepting_is_ambiguous(self):
        class Probe:
            def close(self):
                pass

        arp_output = (
            "? (192.168.139.2) at 2:0:0:0:0:2 on bridge100\n"
            "? (192.168.139.4) at 2:0:0:0:0:4 on bridge100\n"
        )
        result = relay.discover_backend_from_neighbors(
            "bridge100",
            "192.168.139.3",
            self.network,
            1400,
            connector=lambda _address, *, timeout: Probe(),
            runner=lambda *_args, **_kwargs: arp_output,
        )
        self.assertIsNone(result.selected)
        self.assertTrue(result.ambiguous)
        self.assertEqual(result.accepted, ("192.168.139.2", "192.168.139.4"))

    def make_proxy(self, backend, *, connector, arp_runner):
        proxy = relay.CallbackProxy(
            listen_ip="192.168.86.240",
            ports=[1400],
            backend=backend,
            orb_interface="bridge100",
            orb_ip="192.168.139.3",
            orb_network=self.network,
            stop=threading.Event(),
            verbose=False,
            connector=connector,
            arp_runner=arp_runner,
        )
        self.addCleanup(proxy.stop)
        return proxy

    def test_explicit_backend_bypasses_neighbor_discovery(self):
        def unexpected(*_args, **_kwargs):
            raise AssertionError("neighbor discovery should not run")

        proxy = self.make_proxy(
            relay.BackendState("192.168.139.2"),
            connector=unexpected,
            arp_runner=unexpected,
        )
        self.assertEqual(proxy.resolve_backend(1400), "192.168.139.2")

    def test_callback_resolution_bootstraps_backend_from_arp_neighbor(self):
        probes = []

        class Probe:
            def close(self):
                probes.append("closed")

        backend = relay.BackendState(None)
        proxy = self.make_proxy(
            backend,
            connector=lambda address, *, timeout: Probe(),
            arp_runner=lambda *_args, **_kwargs: ARP_OUTPUT,
        )
        self.assertEqual(proxy.resolve_backend(1400), "192.168.139.2")
        self.assertEqual(backend.get(), "192.168.139.2")
        self.assertEqual(probes, ["closed"])


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
        self.assertTrue(backend.observe("192.168.139.2", "outbound Sonos TCP"))
        self.assertFalse(backend.observe("192.168.139.9", "SSDP M-SEARCH"))
        self.assertEqual(backend.get(), "192.168.139.2")

    def test_explicit_address_cannot_be_replaced(self):
        backend = relay.BackendState("192.168.139.2")
        self.assertFalse(backend.observe("192.168.139.9", "outbound Sonos TCP"))
        self.assertEqual(backend.get(), "192.168.139.2")

    def test_wait_wakes_when_address_is_learned(self):
        backend = relay.BackendState(None)
        waiting = threading.Event()
        result = []

        def wait_for_backend():
            waiting.set()
            result.append(backend.wait(1.0))

        thread = threading.Thread(target=wait_for_backend)
        thread.start()
        self.assertTrue(waiting.wait(0.2))
        backend.observe("192.168.139.2", "outbound Sonos TCP")
        thread.join(0.5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, ["192.168.139.2"])

    def test_wait_times_out_when_address_remains_unknown(self):
        backend = relay.BackendState(None)
        self.assertIsNone(backend.wait(0.01))

    def test_tcp_capture_learns_backend_before_any_msearch(self):
        backend = relay.BackendState(None)
        monitor = relay.SSDPRelay(
            lan_ip="192.168.86.240",
            orb_ip="192.168.139.3",
            orb_network=ipaddress.ip_network("192.168.139.0/24"),
            orb_interface="bridge100",
            backend=backend,
            stop=threading.Event(),
            verbose=False,
            minimum_reply_window=5.0,
        )
        monitor.handle_packet(ethernet_tcp_packet())
        self.assertEqual(backend.get(), "192.168.139.2")

    def test_tcp_capture_rejects_source_outside_bridge_subnet(self):
        backend = relay.BackendState(None)
        monitor = relay.SSDPRelay(
            lan_ip="192.168.86.240",
            orb_ip="192.168.139.3",
            orb_network=ipaddress.ip_network("192.168.139.0/24"),
            orb_interface="bridge100",
            backend=backend,
            stop=threading.Event(),
            verbose=False,
            minimum_reply_window=5.0,
        )
        monitor.handle_packet(ethernet_tcp_packet(source_ip="192.168.86.50"))
        self.assertIsNone(backend.get())


class InterfaceTests(unittest.TestCase):
    def test_parses_macos_hexadecimal_interface_netmask(self):
        ifconfig = (
            "bridge100: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
            "\tinet 192.168.139.3 netmask 0xffffff00 broadcast 192.168.139.255\n"
        )
        with mock.patch.object(relay.subprocess, "check_output", return_value=ifconfig):
            network = relay.interface_ipv4_network("bridge100")
        self.assertEqual(str(network), "192.168.139.0/24")


class StartupOrderingTests(unittest.TestCase):
    def test_capture_is_ready_before_callback_listeners_start(self):
        calls = []

        class FakeRelay:
            def __init__(self, **_kwargs):
                pass

            def start(self):
                calls.append("capture ready")

            def wait(self):
                calls.append("normal operation")

            def stop(self):
                pass

        class FakeProxy:
            def __init__(self, **_kwargs):
                pass

            def start(self):
                calls.append("listeners started")

            def stop(self):
                pass

        with (
            mock.patch.object(relay, "SSDPRelay", FakeRelay),
            mock.patch.object(relay, "CallbackProxy", FakeProxy),
            mock.patch.object(
                relay,
                "wait_for_interface_ipv4",
                side_effect=["192.168.86.240", "192.168.139.3"],
            ),
            mock.patch.object(
                relay,
                "interface_ipv4_network",
                return_value=ipaddress.ip_network("192.168.139.0/24"),
            ),
            mock.patch.object(relay.signal, "signal"),
        ):
            result = relay.main(["--ha-ip", "192.168.139.2"])

        self.assertEqual(result, 0)
        self.assertEqual(
            calls,
            ["capture ready", "listeners started", "normal operation"],
        )


if __name__ == "__main__":
    unittest.main()
