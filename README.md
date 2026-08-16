# orbstack-sonos-relay

`orbstack-sonos-relay` is a small compatibility shim for the Sonos integration in Home Assistant Container when it runs under OrbStack on macOS. It relays the two paths Sonos needs: SSDP discovery and UPnP event callbacks.

It is deliberately narrow. It is not a Layer-2 bridge, an mDNS/Bonjour relay, a generic UPnP proxy, a generic TCP forwarder, a Beacon replacement, or a Sonos cloud integration. It does not claim to fix every OrbStack multicast or networking issue.

## Why this is needed

A container using `network_mode: host` shares OrbStack Linux's network namespace—not the Mac's physical `en0` identity. In the tested topology, Home Assistant and the speakers therefore live on opposite sides of a macOS/OrbStack boundary:

```text
Physical Wi-Fi LAN (192.168.86.0/24)

  Sonos speakers                 Mac
  192.168.86.x  <---------->  en0: 192.168.86.240
                                     |
                           macOS / OrbStack boundary
                                     |
                              bridge100: 192.168.139.3
                                     |
                           OrbStack Linux / HA host net
                              HA: 192.168.139.2
```

Home Assistant can initiate ordinary HTTP/SOAP connections to Sonos, but two independent reverse/discovery paths do not naturally cross this boundary in the form Sonos expects.

## Packet flows

### SSDP discovery

Home Assistant sends `ST:ssdp:all` M-SEARCH packets from its OrbStack-side address. The tested installation emits both a multicast and a limited-broadcast copy:

```text
192.168.139.2:ephemeral -> 239.255.255.250:1900
192.168.139.2:ephemeral -> 255.255.255.255:1900
```

The relay captures those packets from `bridge100` through macOS `tcpdump`/BPF, ignores searches originating from the Mac's own bridge address, and deduplicates identical multicast/broadcast copies for a short period. It then sends the original M-SEARCH bytes as a LAN broadcast sourced from the Mac's physical LAN IP.

```text
HA / OrbStack                  relay on Mac                    physical LAN

192.168.139.2:49152  --M-SEARCH-->  capture on bridge100
                                      bind 192.168.86.240:any
                                      broadcast raw M-SEARCH  ----->  :1900

192.168.139.2:49152  <--raw 200 OK--  filter Sonos replies    <-----  Sonos
                         via bridge100  (RINCON_, ZonePlayer,
                                         or Sonos/ marker)
```

The raw Sonos SSDP `200 OK` responses are sent back to the source IP and UDP port of the original HA search. Other UPnP responses are not injected. No speaker IP addresses are configured or hardcoded.

With `--ha-ip auto`, the source of the first suitable M-SEARCH is learned as HA's address. The bridge's own address is excluded, and the learned address is pinned until the process restarts so other SSDP clients cannot make it oscillate.

### UPnP event callbacks

Home Assistant's SoCo event listener runs inside OrbStack, commonly on `192.168.139.2:1400`. The Sonos integration is configured to advertise the Mac's LAN address, so a speaker correctly sends `NOTIFY` requests to `192.168.86.240:1400`. The remaining missing hop is from the Mac to HA.

```text
Sonos speaker                Mac relay                    HA / SoCo

NOTIFY --------------> 192.168.86.240:P  ----------> 192.168.139.2:P
                           TCP listener       same-port TCP connection
```

By default, the daemon listens on TCP ports 1400 through 1499 on the selected LAN address. Each port `P` proxies only to the configured or learned HA address on the same port `P`. The range allows SoCo to choose another listener port when 1400 is occupied. Unavailable ports are reported and skipped; startup fails if none can be bound.

## Requirements

- macOS with OrbStack
- Home Assistant Container using OrbStack host networking
- Python 3.10 or later, with no third-party packages
- `/usr/sbin/tcpdump`
- Home Assistant's Sonos integration and Sonos devices on the physical LAN

The LaunchDaemon runs as root because macOS BPF capture normally requires elevated privileges.

## Installation

Clone the repository, review the scripts and daemon, then run:

```sh
sudo ./install.sh
```

The installer copies the daemon to `/usr/local/libexec/orbstack-sonos-relay/`, writes `/Library/LaunchDaemons/io.github.vaskevich.orbstack-sonos-relay.plist`, and starts it with modern `launchctl bootstrap`. `RunAtLoad` and `KeepAlive` are enabled. If OrbStack has not created `bridge100` yet, the daemon waits rather than exiting in a restart loop.

Defaults can be overridden for one installation:

```sh
sudo env \
  LAN_IFACE=en0 \
  ORB_IFACE=bridge100 \
  HA_IP=auto \
  EVENT_PORTS=1400-1499 \
  PYTHON_BIN=/usr/bin/python3 \
  ./install.sh
```

For deterministic operation, use HA's actual OrbStack-side IPv4 address instead of `auto`:

```sh
sudo env HA_IP=192.168.139.2 ./install.sh
```

Re-running `install.sh` replaces the installed daemon and plist, then restarts the service. It does not modify Home Assistant or OrbStack configuration.

### Home Assistant configuration

Configure the Sonos integration to advertise the Mac's physical LAN address—not the HA/OrbStack address:

```yaml
sonos:
  media_player:
    advertise_addr: 192.168.86.240
```

Restart Home Assistant after changing this setting. Reserve the Mac's LAN address in DHCP (or assign it statically) so `advertise_addr` does not become stale after a lease change. The address must belong to the interface selected by `LAN_IFACE`.

### Choosing interfaces

`en0` and `bridge100` are tested defaults, not universal names. Find the interface used by the default route and inspect its IPv4 address:

```sh
route get default
ifconfig en0
```

List bridge interfaces and inspect likely OrbStack bridges while OrbStack is running:

```sh
ifconfig -l
ifconfig bridge100
```

Choose the physical interface that shares the Sonos LAN for `LAN_IFACE`. Choose the bridge on which HA's `239.255.255.250:1900` or `255.255.255.255:1900` M-SEARCH packets are visible for `ORB_IFACE`. If uncertain, verify traffic directly:

```sh
sudo /usr/sbin/tcpdump -ni bridge100 'udp and dst port 1900'
```

Interface names and addresses can change when network services or OrbStack configuration change; reinstall with updated overrides when necessary.

## Logs and troubleshooting

Show launchd state and follow both logs:

```sh
sudo launchctl print system/io.github.vaskevich.orbstack-sonos-relay
sudo tail -f /var/log/orbstack-sonos-relay.log \
  /var/log/orbstack-sonos-relay.err.log
```

Useful checks:

- `Waiting for interface bridge100` means OrbStack has not created the configured bridge or it has no IPv4 address yet.
- Confirm the startup diagnostics show the expected LAN IP, bridge IP, HA mode/address, and callback ports.
- In auto mode, trigger a Home Assistant Sonos discovery and look for `HA: learned and pinned OrbStack address ...`. Callbacks arriving before that point are rejected; set `HA_IP` explicitly if this timing is undesirable.
- Port warnings identify callback listeners already occupied by another process. A partial range is usable; no available ports is fatal.
- Use `sudo lsof -nP -iTCP:1400 -sTCP:LISTEN` (changing the port as needed) to identify a conflict.
- If searches appear on the bridge but no Sonos replies are forwarded, verify the Mac and speakers share the selected LAN, macOS firewall policy permits the traffic, and LAN client isolation is disabled.
- Reinstall with the right interface names or a deterministic `HA_IP` after correcting configuration.

For foreground diagnostics, stop the LaunchDaemon and invoke the installed program with `--verbose`; do not run two copies because their callback ports will conflict:

```sh
sudo launchctl bootout system/io.github.vaskevich.orbstack-sonos-relay
sudo /usr/bin/python3 \
  /usr/local/libexec/orbstack-sonos-relay/orbstack-sonos-relay.py \
  --lan en0 --orb bridge100 --ha-ip auto --verbose
```

Re-run `install.sh` to restore and start the LaunchDaemon afterward.

## Uninstall

```sh
sudo ./uninstall.sh
```

This boots out the LaunchDaemon and removes its plist and installed program. Log files are deliberately preserved in `/var/log`; remove them manually if desired.

## Security

Read and understand the daemon before installing it:

- It runs as root to capture packets with `tcpdump`/BPF.
- It binds TCP 1400-1499 on the selected physical LAN address by default.
- Those listeners proxy only to the configured/learned HA backend on the same TCP port; they are not arbitrary forwarding endpoints.
- SSDP responses are injected into HA only when they are HTTP 200 responses containing a Sonos-looking `RINCON_`, `ZonePlayer`, or `Sonos/` marker. This is a useful scope filter, not cryptographic authentication.
- A device on the LAN can connect to the callback listeners or forge UDP content. Treat the physical LAN and the configured HA backend as part of the trust boundary. Do not deploy this unchanged on an untrusted LAN.

Reducing `EVENT_PORTS` to the ports your installation actually uses narrows the exposed listener range, but ensure the range still covers any port SoCo may select.

## Limitations

- This handles only the tested Home Assistant Sonos SSDP and event-callback mismatch across OrbStack/macOS.
- It supports Ethernet-framed IPv4 UDP capture, with at most one VLAN tag. IPv6 and fragmented IPv4 M-SEARCH are not relayed.
- Auto HA discovery depends on observing a suitable M-SEARCH and intentionally pins the first non-bridge source until restart. Use `HA_IP` when more than one relevant SSDP client is present or deterministic startup is important.
- The SSDP classifier uses recognizable Sonos response markers; it is not device authentication.
- Changes to macOS, OrbStack, Home Assistant, SoCo, interface naming, firewall behavior, or Sonos firmware may require new validation.
- This does not relay multicast generally and does not make HA literally share the Mac's physical network identity.
- mDNS/Bonjour is explicitly out of scope. Beacon or another mDNS solution can be used independently for HomeKit, Bonjour, and similar services.

## Development

All tests use synthetic packets and the Python standard library; root, tcpdump, OrbStack, Home Assistant, and Sonos hardware are not needed:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile orbstack-sonos-relay.py tests/test_relay.py
sh -n install.sh uninstall.sh
```

## License

MIT
