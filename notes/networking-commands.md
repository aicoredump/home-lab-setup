# Networking Commands — Working Notes

Reference notes written while building the lab (M0/M1). Everything here was used
to diagnose a real problem in this lab, not copied from a manual.

## The `ip` command

`ip` replaces the deprecated `ifconfig`/`route` tools. The syntax is
`ip <object> <action>`, and the objects map cleanly onto OSI layers — which makes
the tool itself a diagnostic ladder:

| Command | Layer | Shows |
|---|---|---|
| `ip link` | 2 | NICs, MAC addresses, link state (UP/DOWN) |
| `ip addr` / `ip a` | 3 | IP addresses assigned to each NIC |
| `ip route` | 3 | routing table — which NIC reaches which network |
| `ip neigh` | 2/3 boundary | ARP cache: IP → MAC mappings |

Abbreviations work as long as they stay unambiguous (`ip a` = `ip addr` =
`ip address`). The default action is `show`, so `ip a` and `ip a show` are
equivalent.

### Diagnostic order

**`ip link` → `ip a` → `ip route` → `ip neigh`**

Work upward from the bottom; the first layer that fails is the cause. This is
exactly how the Kali interface problem was found: `ip link` showed `eth1` as UP,
so layer 2 was fine, but `ip a` showed no address — the fault was layer 3, not
cabling or the virtual switch.

### Reading `ip -brief a`

```
lo     UNKNOWN  127.0.0.1/8 ::1/128
eth0   UP       172.16.110.128/24
eth1   UP       172.16.124.129/24
```

- `UP` means the link works. **An interface can be UP with no address** — that is
  layer 2 working and layer 3 unconfigured.
- `/24` is the prefix length: the first 24 bits identify the network, so
  everything in `172.16.124.x` is on the same local segment.
- `fe80::...` addresses are IPv6 link-local, assigned automatically. Ignore them
  unless working with IPv6 specifically.
- `metric N` is the route cost — lower wins when two routes compete.

### Reading `ip route`

```
default via 172.16.110.2 dev enp2s0 proto dhcp src 172.16.110.130 metric 100
172.16.124.0/24 dev enp26s0 proto kernel scope link src 172.16.124.128 metric 1024
```

- `default via <gw> dev <nic>` — anything not matching a more specific route goes
  out this NIC, to this gateway. This line identifies the path to the internet.
- `scope link` — the network is directly reachable, no router involved. These are
  neighbours in the ARP sense.
- **No default route on an interface means nothing leaves the lab through it.**
  This is how network isolation is verified, rather than assumed.
- More than one default route means traffic selection becomes unpredictable —
  worth checking whenever two adapters are active.

### ARP cache: `ip neigh`

`neigh` is short for *neighbour* — a device on the same local segment, reachable
without a router. The table caches IP → MAC mappings resolved by ARP.

Why it exists: to put a frame on the wire, the sender needs the destination MAC,
because layer 2 has no concept of IP addresses. It broadcasts "who has this IP",
gets an answer, and caches it so it does not have to ask again for every packet.

States to recognise:

| State | Meaning |
|---|---|
| `REACHABLE` | confirmed recently |
| `STALE` | entry exists but is unverified; will be revalidated on next use |
| `INCOMPLETE` | request sent, no reply — host absent or not responding |

`ip neigh flush all` clears the cache and forces a fresh ARP exchange on the next
connection. Required before capturing ARP traffic — without it, the request never
appears on the wire and there is nothing to observe.

Conceptually this is a layer-2 cache in the same way DNS caching is a layer-7
cache: ask once, remember, avoid broadcasting on every request. And like a DNS
cache, it can be poisoned — ARP spoofing is a classic local-network MITM
technique, relevant again in the detection module.

## NetworkManager: `nmcli`

| Command | Purpose |
|---|---|
| `nmcli device status` | device states and which profile owns each one |
| `nmcli connection show` | list of connection profiles with UUIDs and bound devices |
| `nmcli connection add type ethernet con-name <name> ifname <nic>` | new profile pinned to a specific NIC |
| `nmcli connection up <name>` | activate a **named** profile |
| `nmcli device connect <nic>` | activate *whichever* profile matches the device |

**The distinction between the last two matters.** A default profile such as
"Wired connection 1" is not bound to any device, and a profile can only be active
on one device at a time. Using `device connect` on a second NIC therefore moves
that profile off the first NIC, leaving it without an address — which looks
exactly like "only one adapter can be connected at a time" but is nothing of the
kind. Creating one profile per NIC with `ifname` resolves it permanently;
profiles persist in `/etc/NetworkManager/system-connections/` and come back up
after a reboot.

Note that interface naming differs between distributions: Kali uses the classic
`eth0`/`eth1`, Ubuntu Server uses predictable names like `enp2s0`/`enp26s0`. Easy
to mix up when selecting a capture interface.

## Connectivity testing

```bash
ping -c 3 <ip>              # ICMP reachability
ssh user@<ip>               # service-level test
```

Interpreting failures is more useful than the success case:

| Result | Meaning |
|---|---|
| replies, 0% loss | network path works end to end |
| **Connection refused** | packet arrived, host replied with TCP RST — nothing listening on that port. The network is fine; the service is missing. |
| **Connection timed out** | silence — filtered by a firewall, or host unreachable |

The refused/timeout distinction is the first thing to check when a service test
fails, since it separates a network problem from a service problem in one step.

## Wireshark in a two-adapter setup

Capture on the **host-only interface by name**, never on "any" and never on the
NAT interface. With both adapters active, capturing broadly pulls in package
updates, DNS lookups and background traffic, which buries the traffic actually
under test.

Display filters used for the first capture:

```
arp                 # layer 2 address resolution
icmp                # ping traffic
tcp.port == 22      # the SSH session
tcp.flags.syn == 1  # connection establishment only
```

Note: declining Fusion's promiscuous-mode prompt limits capture to traffic
addressed to this host plus broadcasts. That is sufficient for observing one's
own sessions; it is not sufficient for capturing traffic between two other
machines on the segment.
