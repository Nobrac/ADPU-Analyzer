# How the verdict works

[← Documentation](README.md)

Every pending account lands in a list — **clear** or **blocked** — and both are itemised: the tool shows its reasoning rather than asking you to trust a green line. Clear accounts also carry a **confidence**, because "we found nothing" and "we could not look" are not the same answer.

| Confidence | Meaning |
| --- | --- |
| **Proven** | AES key material was observed in the logs, the account really did authenticate inside the window, every controller in its domain was fully audited, completely read and new enough to report the modern 4768 fields — and the window was at least **14 days**. |
| **Plausible** | No blocker found, but nothing positively confirmed — typically a quiet account, partial audit coverage, a controller that was only partly read, or a window shorter than 14 days. |
| **Unknown** | The checks could not look at all. A clean result here means nothing whatsoever. |

> [!IMPORTANT]
> The log-based checks are **backward-looking**. They see what is in the current event logs, and only where auditing was enabled. An account that simply has not used NTLM *recently* looks identical to one that never will — which is exactly what the confidence column is there to tell you.

## Evidence is scoped to the account's own domain

A controller in another domain never authenticates this account, so counting it as coverage would overstate the case. Each account is judged against the controllers of **its own** domain, resolved from the account's SID rather than from whichever group happened to contain it. That matters for `Builtin\Administrators`, which is domain-local and can hold users from other domains in the forest.

## Members homed outside the reviewed scope

Reviewing one domain routinely turns up admins that live in a sibling domain. A privileged member whose own domain was not part of the run gets a **third state**, alongside clear and blocked: one line, under its real domain name, with no verdict. Judging it would mean borrowing another domain's evidence — and since event 4776 carries only an account name, an `admin` that exists once per domain would otherwise collect every domain's NTLM findings. These members count as a coverage gap (exit code `2`), not as blockers.

To see only the domain you picked, `-StrictScope` drops them before anything downstream sees them — no section, no counts, no effect on the exit code:

```powershell
.\ADPU-Analyzer.ps1 -Domain corp.example.net -StrictScope
```

It is not the default, because a foreign account holding admin rights in your domain is usually something you want to know about.

## Break-glass accounts

At least one emergency admin account should stay **outside** Protected Users, so that a side effect nobody foresaw cannot lock out every administrator at once. The built-in Administrator (RID 500) is always treated that way, even when renamed; `-BreakGlass` adds more:

```powershell
.\ADPU-Analyzer.ps1 -BreakGlass 'CORP\emergency', 'S-1-5-21-...-1190'
```

These accounts get their own section — neither *clear* (no enrolment command is printed for them) nor *blocked* — and they do not affect the exit code. If one of them is already enrolled, that is flagged as a hint.

## The krbtgt trap

The *Ticket Encryption Type* in event 4768 is the encryption of the TGT itself — which the KDC picks from the **krbtgt** account's keys, on every build. It says nothing about the account that asked. A krbtgt without AES makes *every* account look like an RC4 user; a krbtgt with AES hides an account that really does negotiate RC4.

What the client and the KDC actually negotiated is in a separate field, *Session Key Encryption Type* (`SessionKeyEncryptionType`), which controllers running Server 2019+, or Server 2016 with the January 2025 cumulative update, report alongside `AccountAvailableKeys` and `ClientAdvertizedEncryptionTypes`. The tool uses:

- **Newer controllers** — the session-key type decides. The ticket field is ignored.
- **Older controllers** — the ticket field is all there is, so it is used as weaker evidence and reported as such (`WeakKerbLegacy`). If krbtgt permits no AES, it is downgraded to a domain-wide warning instead: fix krbtgt first, then re-run.

Whether a controller reports the newer fields is read from its own event manifest and from the events themselves, per event — not inferred from an event version number. The report shows which controllers are which (`4768 v2` / `legacy`).

Only an **explicit, non-zero** `msDS-SupportedEncryptionTypes` without an AES bit counts as a krbtgt problem. Absent or `0` means the KDC default applies, which includes AES from the 2008 functional level — the normal state of a healthy krbtgt. The password age is reported alongside, because a krbtgt password that predates the functional-level raise has no AES keys no matter what the attribute says.
