# Windows Event Log — Audit Configuration and PowerShell Access

Working notes from enabling logon auditing on the Windows 11 Pro lab VM and
pulling security events with PowerShell. Everything below was run and verified
on this lab, not copied from documentation.

## Why this matters

Event ID **4625** (failed logon) is the raw signal behind brute-force detection
(MITRE ATT&CK T1110). A SIEM rule for password spraying is, at its core, "N
events of 4625 for the same target within M seconds" — so being able to produce
and read these events locally is a prerequisite for writing that rule in the SOC
module.

By default Windows 11 does **not** record failed logons in enough detail. Audit
policy must be configured first.

## Enabling logon auditing

Local Group Policy Editor (`gpedit.msc` — requires Windows Pro; Home lacks it):

```
Computer Configuration
└─ Windows Settings
   └─ Security Settings
      └─ Advanced Audit Policy Configuration
         └─ System Audit Policies
            └─ Logon/Logoff
               ├─ Audit Logon   → Success and Failure
               └─ Audit Logoff  → Success
```

Apply and verify (elevated console):

```powershell
gpupdate /force
auditpol /get /category:*
```

Expected under Logon/Logoff: `Logon  Success and Failure`.

Two things caught me here:

- **`auditpol` returned `0x00000522` ("client does not hold the required
  privilege").** The console was not elevated. Running from an administrator
  account is not the same as running elevated — UAC splits the token, and the
  default shell gets the restricted half. Open **Terminal (Administrator)**
  explicitly; the window title must say "Administrator". Same applies to reading
  the Security log.
- The Polish-language UI maps as: *Konfiguracja zaawansowanych zasad inspekcji*
  = Advanced Audit Policy Configuration, *Logowanie/wylogowywanie* =
  Logon/Logoff, *Przeprowadź inspekcję logowania* = Audit Logon.

## Generating test events

Lock the screen (`Win+L`), enter a wrong password three times, then log in
correctly. This produces three 4625 events followed by one 4624.

## Reading events with PowerShell

Use `Get-WinEvent`. `Get-EventLog` is deprecated and cannot see modern logs.

Basic query:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
```

Result on this lab:

```
TimeCreated          Id   Message
5.09.2026 19:28:48   4625 An account failed to log on...
5.09.2026 19:28:46   4625 An account failed to log on...
5.09.2026 19:28:44   4625 An account failed to log on...
```

The regular two-second spacing is the fingerprint of a human typing. A tool-driven
brute force produces tens of events per second — that timing difference is the
first thing a detection rule keys on.

### Filter at the source, not in the pipeline

```powershell
# Fast — filter is pushed to the event log engine
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}

# Slow — pulls the entire log, then filters in PowerShell
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 }
```

Same principle as `WHERE` in SQL versus filtering after `fetchAll()`. On a large
Security log the difference is seconds versus minutes.

### Extracting fields

Event data lives in `$_.Properties`, an array with fixed positions per event ID.
For 4625 (verified on this lab — my first attempt used index 8 for LogonType and
got `%%2313`, a resource-string reference that is actually FailureReason):

| Index | Field | Meaning |
|---|---|---|
| 5 | TargetUserName | account that was targeted |
| 7 | Status | high-level failure code |
| 8 | FailureReason | resource string (`%%2313` = unknown user or bad password) |
| 9 | SubStatus | specific reason for failure |
| 10 | LogonType | how the logon was attempted |
| 13 | WorkstationName | source host name |
| 19 | IpAddress | source IP (`127.0.0.1` or `-` for local console logons, depending on Windows build) |

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 |
  Select-Object TimeCreated,
    @{n='User';      e={$_.Properties[5].Value}},
    @{n='Status';    e={'0x{0:X}' -f $_.Properties[7].Value}},
    @{n='SubStatus'; e={'0x{0:X}' -f $_.Properties[9].Value}},
    @{n='LogonType'; e={$_.Properties[10].Value}},
    @{n='SrcIP';     e={$_.Properties[19].Value}} |
  Format-Table -AutoSize
```

`@{n=...; e={...}}` is a *calculated property* — a mapping function that derives a
new column from an expression, the PowerShell equivalent of `array_map` with
field selection.

Verified output on this lab:

```
TimeCreated          User   SubStatus   LogonType  SrcIP
5.09.2026 19:28:48   kamil  0xC000006A          2  127.0.0.1
5.09.2026 19:28:46   kamil  0xC000006A          2  127.0.0.1
5.09.2026 19:28:44   kamil  0xC000006A          2  127.0.0.1
```

Wrong password, interactive logon at the console, loopback source — exactly what
three manual attempts at the lock screen should look like.

### Status vs SubStatus — a correction

I expected `Status` to show `0xC000006A` (wrong password). It showed
`0xC000006D`. Both are correct; they answer different questions:

- **Status `0xC000006D`** — generic "logon failure". Present on nearly every 4625.
- **SubStatus** carries the reason: `0xC000006A` wrong password,
  `0xC0000064` user does not exist, `0xC0000234` account locked out,
  `0xC0000072` account disabled.

For detection this distinction matters: a burst of `0xC0000064` means someone is
enumerating usernames; a burst of `0xC000006A` against one account means they
already know the account and are guessing the password.

### Logon types worth recognising

| Type | Meaning | Appears when |
|---|---|---|
| 2 | Interactive | keyboard at the console (this lab) |
| 3 | Network | SMB, shares, some RDP paths |
| 10 | RemoteInteractive | RDP |
| 5 | Service | service account start |

Brute force over the network shows as type 3 or 10, never 2 — the field alone
tells you whether the attacker is at the keyboard or coming over the wire.

**Lesson on field indices:** never trust a documented index without running the
query. Two indices I assumed from memory were wrong; both were caught only because
the output was inspected rather than pasted into notes. `Properties` positions are
stable per event ID, but they differ between IDs, and guidance found online is
frequently off by one.

## PowerShell pipeline — the one thing that differs from bash

The pipeline passes **objects**, not text. `$_.TimeCreated` works without
parsing because each item is a structured object with typed properties. Closer
to a method chain on a typed collection in TypeScript than to `grep | awk`.
`Where-Object` ≈ `array_filter`, `Select-Object` ≈ `array_map` with field
projection.

## Related event IDs

| ID | Meaning |
|---|---|
| 4624 | successful logon |
| 4625 | failed logon |
| 4634 | logoff |
| 4672 | special privileges assigned (admin logon) |
| 4740 | account locked out |
| 4688 | process creation (requires separate audit subcategory) |

## Open items

- Audit Logoff did not apply on first pass — re-enable and verify with `auditpol`.
- Enable *Audit Process Creation* (4688) with command-line logging before M2.
- Consider switching the system display language to English: documentation,
  Sentinel dashboards, and error messages are all English, and mental
  translation of policy names is friction at every step.
