#!/usr/bin/env python3
"""Relay Home Assistant Sonos traffic across OrbStack's macOS boundary."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import selectors
import signal
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass


VERSION = "1.0.1"
SSDP_MULTICAST = "239.255.255.250"
SSDP_BROADCAST = "255.255.255.255"
SSDP_PORT = 1900
DEFAULT_EVENT_PORTS = "1400-1499"
TCPDUMP = "/usr/sbin/tcpdump"
IFCONFIG = "/sbin/ifconfig"
PCAP_LINKTYPE_ETHERNET = 1
SONOS_HTTP_PORT = 1400
CAPTURE_FILTER = "(udp and dst port 1900) or (tcp and dst port 1400)"


def log(message: str) -> None:
    print(message, flush=True)


def debug(enabled: bool, message: str) -> None:
    if enabled:
        log(message)


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges into sorted ports."""
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if "-" in item:
                first_text, last_text = item.split("-", 1)
                first, last = int(first_text), int(last_text)
                if first > last:
                    raise ValueError(f"invalid descending range: {item}")
                ports.update(range(first, last + 1))
            else:
                ports.add(int(item))
        except ValueError as exc:
            if str(exc).startswith("invalid descending"):
                raise
            raise ValueError(f"invalid port or range: {item or value}") from exc

    if not ports:
        raise ValueError("no event callback ports specified")
    invalid = next((port for port in ports if not 1 <= port <= 65535), None)
    if invalid is not None:
        raise ValueError(f"port outside 1-65535: {invalid}")
    return sorted(ports)


def parse_ssdp_headers(payload: bytes) -> dict[str, str]:
    """Return case-insensitive SSDP/HTTP headers with lower-case names."""
    text = payload.decode("latin-1", errors="replace")
    headers: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n")[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def looks_like_sonos_response(payload: bytes) -> bool:
    """Accept only SSDP 200 responses containing known Sonos markers."""
    first_line = payload.splitlines()[0].strip().upper() if payload else b""
    if first_line != b"HTTP/1.1 200 OK":
        return False
    lowered = payload.lower()
    return any(marker in lowered for marker in (b"rincon_", b"zoneplayer", b"sonos/"))


@dataclass(frozen=True)
class MSearchPacket:
    source_ip: str
    source_port: int
    destination_ip: str
    payload: bytes


@dataclass(frozen=True)
class TCPPacket:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int


def parse_msearch_packet(packet: bytes) -> MSearchPacket | None:
    """Parse an Ethernet/IPv4/UDP SSDP M-SEARCH captured by tcpdump."""
    if len(packet) < 14:
        return None
    ether_type = struct.unpack("!H", packet[12:14])[0]
    offset = 14
    # bridge100 normally uses Ethernet framing. Accept one 802.1Q or 802.1ad tag.
    if ether_type in (0x8100, 0x88A8):
        if len(packet) < 18:
            return None
        ether_type = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(packet) < offset + 20:
        return None

    ip = packet[offset:]
    version, ihl = ip[0] >> 4, (ip[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip) < ihl + 8 or ip[9] != socket.IPPROTO_UDP:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length < ihl + 8 or len(ip) < total_length:
        return None
    # Fragmented UDP cannot be safely parsed without reassembly.
    flags_fragment = struct.unpack("!H", ip[6:8])[0]
    if flags_fragment & 0x3FFF:
        return None

    udp = ip[ihl:total_length]
    source_port, destination_port, udp_length = struct.unpack("!HHH", udp[:6])
    if destination_port != SSDP_PORT or udp_length < 8 or udp_length > len(udp):
        return None
    destination_ip = socket.inet_ntoa(ip[16:20])
    if destination_ip not in (SSDP_MULTICAST, SSDP_BROADCAST):
        return None
    payload = udp[8:udp_length]
    first_line = payload.splitlines()[0].strip().upper() if payload else b""
    if not first_line.startswith(b"M-SEARCH "):
        return None
    return MSearchPacket(
        source_ip=socket.inet_ntoa(ip[12:16]),
        source_port=source_port,
        destination_ip=destination_ip,
        payload=payload,
    )


def parse_tcp_packet(packet: bytes) -> TCPPacket | None:
    """Parse safe endpoint metadata from an Ethernet/IPv4/TCP packet."""
    if len(packet) < 14:
        return None
    ether_type = struct.unpack("!H", packet[12:14])[0]
    offset = 14
    if ether_type in (0x8100, 0x88A8):
        if len(packet) < 18:
            return None
        ether_type = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(packet) < offset + 20:
        return None

    ip = packet[offset:]
    version, ihl = ip[0] >> 4, (ip[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip) < ihl + 20 or ip[9] != socket.IPPROTO_TCP:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length < ihl + 20 or len(ip) < total_length:
        return None
    if struct.unpack("!H", ip[6:8])[0] & 0x3FFF:
        return None

    tcp = ip[ihl:total_length]
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(tcp):
        return None
    source_port, destination_port = struct.unpack("!HH", tcp[:4])
    return TCPPacket(
        source_ip=socket.inet_ntoa(ip[12:16]),
        source_port=source_port,
        destination_ip=socket.inet_ntoa(ip[16:20]),
        destination_port=destination_port,
    )


class SearchDeduplicator:
    """Suppress HA's identical multicast/broadcast search pair briefly."""

    def __init__(self, window: float = 1.0, retention: float = 20.0) -> None:
        self.window = window
        self.retention = retention
        self._seen: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def accept(self, client: tuple[str, int], payload: bytes, now: float | None = None) -> bool:
        timestamp = time.monotonic() if now is None else now
        key = hashlib.sha256(f"{client[0]}:{client[1]}".encode("ascii") + b"\0" + payload).digest()
        with self._lock:
            previous = self._seen.get(key)
            if previous is not None and timestamp - previous < self.window:
                return False
            self._seen[key] = timestamp
            expired = [key for key, seen_at in self._seen.items() if timestamp - seen_at > self.retention]
            for expired_key in expired:
                del self._seen[expired_key]
        return True


class BackendState:
    """Store a configured HA IP, or learn and pin the first suitable source."""

    def __init__(self, configured_ip: str | None) -> None:
        self.configured_ip = configured_ip
        self.discovered_ip: str | None = None
        self._condition = threading.Condition()

    @property
    def automatic(self) -> bool:
        return self.configured_ip is None

    def get(self) -> str | None:
        with self._condition:
            return self.configured_ip or self.discovered_ip

    def wait(self, timeout: float) -> str | None:
        """Wait briefly for auto-detection, returning immediately if configured."""
        with self._condition:
            self._condition.wait_for(
                lambda: self.configured_ip is not None or self.discovered_ip is not None,
                timeout=timeout,
            )
            return self.configured_ip or self.discovered_ip

    def observe(self, address: str, source: str = "observed traffic") -> bool:
        with self._condition:
            if self.configured_ip:
                return address == self.configured_ip
            if self.discovered_ip is None:
                self.discovered_ip = address
                log(f"HA: learned and pinned OrbStack address {address} from {source}")
                self._condition.notify_all()
                return True
            return address == self.discovered_ip


def interface_ipv4(name: str) -> str:
    output = subprocess.check_output([IFCONFIG, name], text=True, stderr=subprocess.DEVNULL)
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) >= 2 and fields[0] == "inet":
            return fields[1]
    raise RuntimeError(f"no IPv4 address found on interface {name}")


def interface_ipv4_network(name: str) -> ipaddress.IPv4Network | None:
    """Read the interface subnet from macOS ifconfig's hexadecimal netmask."""
    output = subprocess.check_output([IFCONFIG, name], text=True, stderr=subprocess.DEVNULL)
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) < 4 or fields[0] != "inet" or "netmask" not in fields:
            continue
        try:
            address = ipaddress.IPv4Address(fields[1])
            mask_text = fields[fields.index("netmask") + 1]
            mask = ipaddress.IPv4Address(int(mask_text, 16) if mask_text.startswith("0x") else mask_text)
            network = ipaddress.ip_network(f"{address}/{mask}", strict=False)
        except (ValueError, IndexError):
            return None
        return network if isinstance(network, ipaddress.IPv4Network) else None
    return None


def wait_for_interface_ipv4(name: str, stop: threading.Event) -> str:
    announced = False
    while not stop.is_set():
        try:
            return interface_ipv4(name)
        except (OSError, subprocess.CalledProcessError, RuntimeError):
            if not announced:
                log(f"Waiting for interface {name} and an IPv4 address (is OrbStack running?)")
                announced = True
            stop.wait(2.0)
    raise RuntimeError("stopping while waiting for interfaces")


class SSDPRelay:
    def __init__(self, *, lan_ip: str, orb_ip: str,
                 orb_network: ipaddress.IPv4Network | None, orb_interface: str,
                 backend: BackendState, stop: threading.Event, verbose: bool,
                 minimum_reply_window: float) -> None:
        self.lan_ip = lan_ip
        self.orb_ip = orb_ip
        self.orb_network = orb_network
        self.orb_interface = orb_interface
        self.backend = backend
        self.stop_event = stop
        self.verbose = verbose
        self.minimum_reply_window = minimum_reply_window
        self.deduplicator = SearchDeduplicator()
        self.process: subprocess.Popen[bytes] | None = None
        self._capture_thread: threading.Thread | None = None
        self._capture_ready = threading.Event()
        self._capture_error: Exception | None = None
        self._relay_threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()

    def handle_packet(self, packet: bytes) -> None:
        tcp = parse_tcp_packet(packet)
        if tcp is not None:
            if (
                self.backend.automatic
                and tcp.destination_port == SONOS_HTTP_PORT
                and tcp.source_ip != self.orb_ip
                and (
                    self.orb_network is None
                    or ipaddress.IPv4Address(tcp.source_ip) in self.orb_network
                )
            ):
                self.backend.observe(tcp.source_ip, "outbound Sonos TCP")
            return

        search = parse_msearch_packet(packet)
        if search is None or search.source_ip == self.orb_ip:
            return
        if (
            self.orb_network is not None
            and ipaddress.IPv4Address(search.source_ip) not in self.orb_network
        ):
            return
        if not self.backend.observe(search.source_ip, "SSDP M-SEARCH"):
            debug(self.verbose, f"SSDP: ignored M-SEARCH from non-HA client {search.source_ip}")
            return
        client = (search.source_ip, search.source_port)
        if not self.deduplicator.accept(client, search.payload):
            debug(self.verbose, f"SSDP: suppressed duplicate from {client[0]}:{client[1]}")
            return
        thread = threading.Thread(target=self._relay_thread, args=(search.payload, client),
                                  name=f"ssdp-{client[0]}:{client[1]}", daemon=True)
        with self._threads_lock:
            self._relay_threads.add(thread)
        thread.start()

    def _relay_thread(self, payload: bytes, client: tuple[str, int]) -> None:
        try:
            self.relay(payload, client)
        finally:
            with self._threads_lock:
                self._relay_threads.discard(threading.current_thread())

    def relay(self, payload: bytes, client: tuple[str, int]) -> None:
        outbound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        reply_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            outbound.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            outbound.bind((self.lan_ip, 0))
            outbound.settimeout(0.25)
            # Force injected replies onto the macOS side of bridge100.
            reply_socket.bind((self.orb_ip, 0))
            headers = parse_ssdp_headers(payload)
            try:
                mx = int(headers.get("mx", "3"))
            except ValueError:
                mx = 3
            reply_window = max(self.minimum_reply_window, max(1, min(mx, 10)) + 1.0)
            debug(self.verbose, f"SSDP: {client[0]}:{client[1]} ST={headers.get('st', 'unknown')} "
                  f"-> {SSDP_BROADCAST}:{SSDP_PORT} from {self.lan_ip}:{outbound.getsockname()[1]}")
            outbound.sendto(payload, (SSDP_BROADCAST, SSDP_PORT))
            deadline = time.monotonic() + reply_window
            forwarded, ignored = 0, 0
            responders: set[str] = set()
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                try:
                    data, source = outbound.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not looks_like_sonos_response(data):
                    ignored += 1
                    continue
                try:
                    reply_socket.sendto(data, client)
                except OSError as exc:
                    log(f"SSDP: could not return reply to {client[0]}:{client[1]}: {exc}")
                    continue
                forwarded += 1
                responders.add(source[0])
                debug(self.verbose, f"SSDP: Sonos reply {source[0]}:{source[1]} -> {client[0]}:{client[1]}")
            log(f"SSDP: {client[0]}:{client[1]} forwarded {forwarded} replies from "
                f"{len(responders)} Sonos device(s)" + (f"; ignored {ignored} other replies" if ignored else ""))
        except OSError as exc:
            log(f"SSDP: relay failed for {client[0]}:{client[1]}: {exc}")
        finally:
            outbound.close()
            reply_socket.close()

    def start(self) -> None:
        """Start capture and wait until tcpdump's pcap stream is ready."""
        self._capture_thread = threading.Thread(
            target=self._capture_main,
            name="bridge-capture",
            daemon=True,
        )
        self._capture_thread.start()
        if not self._capture_ready.wait(timeout=10.0):
            self.stop()
            raise RuntimeError("timed out waiting for tcpdump capture to become ready")
        if self._capture_error is not None:
            raise self._capture_error

    def _capture_main(self) -> None:
        try:
            self.run()
        except Exception as exc:
            self._capture_error = exc
        finally:
            self._capture_ready.set()

    def wait(self) -> None:
        """Wait for capture to stop and propagate an unexpected failure."""
        thread = self._capture_thread
        if thread is None:
            raise RuntimeError("capture has not been started")
        while thread.is_alive() and not self.stop_event.is_set():
            thread.join(timeout=0.5)
        if self._capture_error is not None:
            raise self._capture_error

    def run(self) -> None:
        command = [TCPDUMP, "-n", "-U", "-s", "0", "-i", self.orb_interface,
                   "-w", "-", CAPTURE_FILTER]
        log(f"Capture: monitoring HA/Sonos SSDP and TCP on {self.orb_interface}")
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE)
        assert self.process.stdout is not None
        stream = self.process.stdout
        global_header = stream.read(24)
        if len(global_header) != 24:
            status = self.process.poll()
            raise RuntimeError(f"could not read tcpdump pcap header (status={status})")
        magic = global_header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise RuntimeError(f"unexpected pcap magic {magic.hex()}")
        linktype = struct.unpack(endian + "I", global_header[20:24])[0]
        if linktype != PCAP_LINKTYPE_ETHERNET:
            raise RuntimeError(f"tcpdump returned unsupported pcap link type {linktype}; expected Ethernet")
        self._capture_ready.set()

        while not self.stop_event.is_set():
            header = stream.read(16)
            if len(header) != 16:
                break
            _, _, captured_length, _ = struct.unpack(endian + "IIII", header)
            if captured_length > 1_000_000:
                raise RuntimeError(f"implausible pcap packet length {captured_length}")
            packet = stream.read(captured_length)
            if len(packet) != captured_length:
                break
            self.handle_packet(packet)
        if not self.stop_event.is_set():
            status = self.process.wait(timeout=2)
            raise RuntimeError(f"tcpdump exited unexpectedly (status={status})")

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            else:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    else:
                        process.wait(timeout=2)
        with self._threads_lock:
            threads = list(self._relay_threads)
        for thread in threads:
            thread.join(timeout=1.0)
        capture_thread = self._capture_thread
        if capture_thread is not None and capture_thread is not threading.current_thread():
            capture_thread.join(timeout=2.0)


class CallbackProxy:
    """Proxy every selected LAN TCP port to the same port on HA."""

    def __init__(self, *, listen_ip: str, ports: list[int], backend: BackendState,
                 stop: threading.Event, verbose: bool) -> None:
        self.listen_ip = listen_ip
        self.ports = ports
        self.backend = backend
        self.stop_event = stop
        self.verbose = verbose
        self.selector = selectors.DefaultSelector()
        self.listeners: list[socket.socket] = []
        self.thread: threading.Thread | None = None
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()

    def start(self) -> None:
        bound: list[int] = []
        for port in self.ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((self.listen_ip, port))
                listener.listen(64)
                listener.setblocking(False)
            except OSError as exc:
                listener.close()
                log(f"Events: port {self.listen_ip}:{port} unavailable: {exc}")
                continue
            self.selector.register(listener, selectors.EVENT_READ, data=port)
            self.listeners.append(listener)
            bound.append(port)
        if not bound:
            raise RuntimeError("could not bind any Sonos event callback ports")
        skipped = len(self.ports) - len(bound)
        description = str(bound[0]) if len(bound) == 1 else f"{bound[0]}-{bound[-1]} ({len(bound)} ports)"
        log(f"Events: listening on {self.listen_ip}:{description}" +
            (f"; {skipped} requested port(s) unavailable" if skipped else ""))
        self.thread = threading.Thread(target=self._accept_loop, name="callback-accept", daemon=True)
        self.thread.start()

    def _accept_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                events = self.selector.select(timeout=0.5)
            except (OSError, ValueError):
                return
            for key, _ in events:
                try:
                    client, address = key.fileobj.accept()
                except OSError:
                    continue
                threading.Thread(target=self._handle_connection, args=(client, address, key.data),
                                 name=f"callback-{key.data}", daemon=True).start()

    def _track(self, *sockets: socket.socket) -> None:
        with self._connections_lock:
            self._connections.update(sockets)

    def _untrack(self, *sockets: socket.socket) -> None:
        with self._connections_lock:
            self._connections.difference_update(sockets)

    def _handle_connection(self, client: socket.socket, address: tuple[str, int], port: int) -> None:
        backend_ip = self.backend.wait(timeout=0.75)
        if backend_ip is None:
            log(f"Events: rejected callback from {address[0]}:{address[1]} on :{port}; "
                "HA address was not learned within 0.75 seconds")
            client.close()
            return
        try:
            upstream = socket.create_connection((backend_ip, port), timeout=5)
        except OSError as exc:
            log(f"Events: backend connection to {backend_ip}:{port} failed: {exc}")
            client.close()
            return
        self._track(client, upstream)
        debug(self.verbose, f"Events: {address[0]}:{address[1]} -> {backend_ip}:{port}")
        client.settimeout(120)
        upstream.settimeout(120)

        def pump(source: socket.socket, destination: socket.socket) -> None:
            try:
                while not self.stop_event.is_set():
                    data = source.recv(65536)
                    if not data:
                        break
                    destination.sendall(data)
            except (OSError, TimeoutError):
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        first = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        second = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        first.start()
        second.start()
        first.join()
        second.join()
        self._untrack(client, upstream)
        client.close()
        upstream.close()

    def stop(self) -> None:
        for listener in self.listeners:
            try:
                self.selector.unregister(listener)
            except Exception:
                pass
            listener.close()
        try:
            self.selector.close()
        except OSError:
            pass
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.thread is not None:
            self.thread.join(timeout=1.0)


def ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise argparse.ArgumentTypeError("an IPv4 address is required")
    return str(address)


def ha_ip(value: str) -> str:
    return "auto" if value.lower() == "auto" else ipv4(value)


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Relay HA Sonos discovery and callbacks across OrbStack/macOS")
    parser.add_argument("--lan", default="en0", help="physical LAN interface (default: en0)")
    parser.add_argument("--orb", default="bridge100", help="OrbStack bridge interface (default: bridge100)")
    parser.add_argument("--ha-ip", type=ha_ip, default="auto", help="HA OrbStack IPv4 or auto (default: auto)")
    parser.add_argument("--event-ports", default=DEFAULT_EVENT_PORTS,
                        help=f"callback TCP ports/ranges (default: {DEFAULT_EVENT_PORTS})")
    parser.add_argument("--reply-window", type=positive_float, default=5.0,
                        help="minimum SSDP response window in seconds (default: 5)")
    parser.add_argument("--verbose", action="store_true", help="log individual relay decisions")
    parser.add_argument("--check-config", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.event_ports)
    except ValueError as exc:
        build_parser().error(f"invalid --event-ports: {exc}")
    if args.check_config:
        return 0

    stop_event = threading.Event()
    backend = BackendState(None if args.ha_ip == "auto" else args.ha_ip)
    relay: SSDPRelay | None = None
    proxy: CallbackProxy | None = None

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()
        if relay is not None:
            relay.stop()
        if proxy is not None:
            proxy.stop()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        lan_ip = wait_for_interface_ipv4(args.lan, stop_event)
        orb_ip = wait_for_interface_ipv4(args.orb, stop_event)
        try:
            orb_network = interface_ipv4_network(args.orb)
        except (OSError, subprocess.CalledProcessError):
            orb_network = None
        if backend.get() == orb_ip:
            raise RuntimeError("--ha-ip must not be the macOS bridge address")
        log(f"orbstack-sonos-relay {VERSION}")
        log(f"LAN: {args.lan} = {lan_ip}")
        log(f"ORB: {args.orb} = {orb_ip}")
        log(f"HA:  {backend.get() or 'auto-detect from outbound Sonos TCP or SSDP M-SEARCH'}")
        if orb_network is None:
            log("ORB: warning: could not determine bridge subnet; auto-detection subnet check disabled")
        proxy = CallbackProxy(listen_ip=lan_ip, ports=ports, backend=backend,
                              stop=stop_event, verbose=args.verbose)
        relay = SSDPRelay(lan_ip=lan_ip, orb_ip=orb_ip, orb_network=orb_network,
                          orb_interface=args.orb,
                          backend=backend, stop=stop_event, verbose=args.verbose,
                          minimum_reply_window=args.reply_window)
        relay.start()
        proxy.start()
        relay.wait()
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as exc:
        if not stop_event.is_set():
            log(f"Fatal: {exc}")
            return 1
    finally:
        stop_event.set()
        if relay is not None:
            relay.stop()
        if proxy is not None:
            proxy.stop()
    log("Stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
