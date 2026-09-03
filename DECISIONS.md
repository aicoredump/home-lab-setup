# Home Lab — Architecture Decisions

**Context:** Isolated home lab built as the foundation for an 18-week AI security
curriculum (modules M0–M7).
**Host:** Mac mini, Apple M1, 16 GB RAM, macOS, 512 GB SSD.
**Established:** 2026-08-31 · **Last updated:** 2026-09-03

Format for each decision: **Decision → Rationale → Rejected alternatives**

---

## (a) Hypervisor: VMware Fusion Pro (personal-use license)

**Rationale:** The host is Apple Silicon (ARM64). Fusion Pro is free for personal
use, supports ARM natively, and provides the two capabilities this lab depends on
directly in the GUI: snapshots and an isolated host-only network.

**Rejected alternatives:**
- **VirtualBox** — the original choice in the curriculum, but ARM support is
  experimental and Windows on ARM effectively fails to boot.
- **UTM (QEMU)** — runs on ARM, but snapshot support is rudimentary, and
  snapshots are a hard requirement here.
- **Proxmox** — requires a dedicated x86 machine; no second host available.

---

## (b) Virtual machines and resource allocation

All images are **ARM64**. On Apple Silicon, amd64 images either fail to boot or
run under emulation with a severe performance penalty.

| VM | Role in the lab | RAM | vCPU | Disk |
|---|---|---|---|---|
| Kali Linux (ARM64 installer) | attacker machine, offensive tooling | 4 GB | 2 | 40 GB |
| Ubuntu Server LTS (ARM64) | target host, log source (`auth.log`), SIEM host in M2 | 2 GB | 2 | 25 GB |
| Windows 11 Pro (ARM64) | Event Log, PowerShell, Defender/EDR telemetry in M2 | 4–6 GB | 2–4 | 64 GB |

### Windows 11 Pro, not Home

Home lacks `gpedit.msc` and Advanced Audit Policy Configuration. Without those,
detailed logon auditing (Event ID 4625, mapped to MITRE ATT&CK T1110) and script
execution logging (T1059) cannot be enabled — both are core to the SOC module.
Home also forces a Microsoft account during setup and cannot accept inbound RDP.

### Windows 11 ARM64 ISO instead of the 90-day evaluation VM

Microsoft's "Windows development environment" image is x86 and will not run on
M1. The official Windows 11 ARM64 ISO, left unactivated, provides everything the
curriculum needs (Event Log, PowerShell, Defender); the only restrictions are
cosmetic personalisation features.

### Windows on ARM — working around the OOBE network requirement

The Windows 11 ARM installer ships without a driver for VMware's virtual NIC
(vmxnet3), so the "Let's connect you to a network" screen blocks setup: the
driver only arrives with VMware Tools, which cannot be installed until setup
completes. Workaround:

1. `Shift + Fn + F10` to open a command prompt over the installer.
2. `start ms-cxh:localonly` — creates a local account and skips the network
   requirement (`oobe\bypassnro` is the fallback on older builds).
3. Once at the desktop: **Virtual Machine → Install VMware Tools**, then reboot.

### Disk budget

VMs total roughly 130 GB when fully provisioned. Fusion allocates disk
incrementally, so initial usage is closer to 60–70 GB. Free space at lab
creation: **397 GB**, so VM sizes were not constrained.

**Alert threshold:** below 60 GB free, prune old snapshots before continuing.
Snapshots grow with VM changes, and growth accelerates in M2 once Wazuh and
Elastic indices are in play.

---

## (c) Network topology: two adapters per VM — NAT and host-only, both active

| Fusion mode | Meaning | Role in the lab |
|---|---|---|
| Share with my Mac | NAT | internet access: `apt update`, tooling, TryHackMe VPN |
| Private to my Mac | host-only, isolated lab segment | attacker → target traffic, packet capture |
| Bridged (Autodetect/Wi-Fi/Ethernet) | VM exposed on the home LAN | **never used** |

Subnets assigned by Fusion:

- **NAT** — `172.16.110.0/24`, gateway `172.16.110.2`, DHCP
- **Host-only** — `172.16.124.0/24`, host (Mac) at `172.16.124.1`

| VM | Interfaces | NAT (DHCP) | Host-only (static) |
|---|---|---|---|
| Ubuntu Server | enp2s0 / enp26s0 | 172.16.110.130 | **172.16.124.10** |
| Kali | eth0 / eth1 | 172.16.110.128 | **172.16.124.11** |
| Windows 11 | — | DHCP | TBD |

### Why host-only rather than NAT alone

VMs on NAT can reach each other, so a NAT-only lab appears to work. The problem
is directional: NAT leaves an open outbound path, so ATT&CK simulations planned
for M2 (T1110 brute force, T1059 script execution) would run on machines that can
reach the home network and the internet. A mistyped scan range would leave the
lab. Isolation also produces a far cleaner capture set — on host-only, the only
traffic present is traffic I generated deliberately.

### Known limitation of host-only

Fusion's label is literal: "Private to my **Mac**" means the host itself sits in
the subnet, at `172.16.124.1`. This is not full isolation (VirtualBox's "Internal
Network" would be the equivalent) — it cuts the lab off from the router and other
household devices, but the host remains reachable. Accepted deliberately, since
packet capture and host access to lab services both depend on it.

### Static addressing on the lab segment

DHCP leases shift across reboots, which makes them unusable for agent-based
tooling that stores the manager's address in its configuration — a hard
requirement once Wazuh is deployed in M2. Addresses `.10` and `.11` sit below
Fusion's DHCP pool (which begins around `.128`), so a conflict is not possible.

NAT interfaces stay on DHCP: there is no benefit to fighting Fusion's DHCP server
for addresses on a segment whose only job is reaching the internet.

**Neither host declares a gateway on the lab interface.** The absence of a
default route is the mechanism that keeps the segment isolated, and `ip route` is
how it is verified rather than assumed:

```
default via 172.16.110.2 dev enp2s0 proto dhcp src 172.16.110.130 metric 100
172.16.124.0/24 dev enp26s0 proto kernel scope link src 172.16.124.10
```

Exactly one default route, on the NAT interface. The lab interface carries only a
`scope link` route to its own subnet — directly reachable via ARP, no router
involved. The kernel resolves this by longest-prefix match, so traffic to
`172.16.124.x` takes the specific route while everything else falls through to
the default.

Ubuntu is configured through netplan, in a separate file
(`/etc/netplan/60-lab-static.yaml`) so the cloud-init file managing the NAT
interface stays untouched; `netplan try` applies changes with an automatic
rollback if connectivity breaks. Kali is configured through a NetworkManager
profile bound to the NIC:

```bash
nmcli connection add type ethernet con-name lab ifname eth1 \
  ipv4.method manual ipv4.addresses 172.16.124.11/24
```

### Cost of running two adapters

Tools pick an interface on their own, so they must be pointed explicitly:
`nmap -e <iface>`, and Wireshark capture bound to the host-only interface rather
than "any". Otherwise update traffic and DNS noise contaminate the analysis.

**Rejected alternative:** *Bridged* — places the VM directly on the home LAN with
an address from the router. Maximum exposure, no benefit for this lab.

### Configuration pitfalls encountered during setup

**Kali: one NetworkManager profile shared across two NICs.** After adding the
second adapter, `eth1` came up at layer 2 but had no IP address (layer 3
unconfigured), showing as `disconnected`. Running `nmcli device connect eth1`
activated the existing "Wired connection 1" profile, which is not bound to any
device — so the profile hopped between `eth0` and `eth1`, always leaving one NIC
without an address. The fix is one profile per NIC, pinned with `ifname`.

**A wrong conclusion drawn along the way, worth recording.** After a reboot both
Kali NICs appeared to work, which was read as confirmation that the per-NIC
profiles had been created successfully. `nmcli connection show` later showed no
such profiles existed — `eth1` was simply `disconnected`, and the apparent
success was the old single-profile behaviour reasserting itself. Verifying the
intended mechanism, rather than the symptom, would have caught this immediately.

**Ubuntu** configured its second interface automatically — it uses
netplan/systemd-networkd rather than NetworkManager. Interface naming also
differs between the two distributions (`eth0`/`eth1` on Kali, predictable names
like `enp2s0`/`enp26s0` on Ubuntu), which is easy to confuse when selecting a
capture interface.

---

## (d) Snapshot policy

- A **`clean`** snapshot after each OS installation and first full update, taken
  with the **VM powered off** — on a 16 GB host, snapshotting a running VM also
  captures memory state, making it larger and slower.
- A snapshot **before** any change that is hard to undo: Wazuh/Elastic
  installation in M2, deliberate host infection, Defender configuration
  experiments.
- Naming convention: `YYYY-MM-DD-description`.
- Review and prune snapshots once per module — otherwise disk usage becomes a
  problem around M2.

Snapshots taken so far:

| Snapshot | State captured |
|---|---|
| `2026-09-01-clean-post-install` | base OS, fully updated |
| `2026-09-03-lab-network-configured` | static addressing, isolation verified |

---

## (e) Runtime policy: at most 2 VMs running concurrently

**Rationale:** 16 GB of RAM shared with macOS. The standard working pair is Kali
(4 GB) plus Ubuntu (2 GB), which leaves the host comfortable. Windows runs on its
own, or alongside Ubuntu with its allocation reduced to 4 GB.

**Three VMs at once is not viable on this hardware** — 10–12 GB committed to
guests pushes macOS into swap. No scenario in M0–M2 requires it; attacker →
target exercises always involve a pair.

All three VMs are **installed**; the constraint applies only to how many run
simultaneously.

---

## Open items

- Windows 11: static address on the lab segment, audit policy configuration
  (logon events, process creation).
- Static addressing to be revisited if additional hosts join the lab segment in
  M2 — current allocation reserves `.10`–`.20` for infrastructure.
