# What it checks

[← Documentation](README.md)

Privileged accounts are the recursive membership of a group set, expanded across every domain in scope.

| Scope | Groups |
| --- | --- |
| `Core` (default) | Administrators, Domain Admins, Enterprise Admins, Schema Admins |
| `Extended` | the above plus Account/Server/Print/Backup Operators, Group Policy Creator Owners, Key Admins, Enterprise Key Admins, DnsAdmins |

`-IncludeGroup` folds in anything else, by SID or by name.

## Blockers — these decide the verdict

| Check | Source | Why it blocks |
| --- | --- | --- |
| **NTLM at a controller** | Security **4624**, `AuthenticationPackageName = NTLM` | Members cannot authenticate over NTLM at all. |
| **NTLM anywhere in the estate** | Security **4776** (credential validation) | The case 4624 never sees: NTLM against a member server or workstation reaches the DC as 4776. |
| **NTLM attempts with a stale password** | Security **4776**, failed, with status code | Repeated failures (*wrong password*, *locked out*, …) almost always mean something is still configured to sign this account in over NTLM with an old saved password. The day that password is corrected, it needs NTLM and breaks. The report names the source machines and the status codes; with many different sources it is worded as a possible attack instead. Failures that are only *no such user* are not about this account and stay a hint. |
| **Runs a service or scheduled task** | Security **4624** / **4625**, logon type `5` (service) or `4` (batch), on the domain controllers | The account is a service account in practice. Members get a 4-hour TGT that cannot be renewed, no delegation and no "do not store password" (S4U) tasks. Failed service or task logons (4625) are reported with their status codes — typically a task still configured with an old password. Only logons on the controllers themselves are visible; a task on a member server logs there. |
| **No AES key material** | **4768** → *Available Keys* | Direct evidence from the KDC that the account has no AES key. Beats every guess. |
| **Password predates the group** | `pwdLastSet` vs. the group's `whenCreated` | Fallback for the above, used **only** when no key material was observed. |
| **DES/RC4 Kerberos** | **4768** *Session Key Encryption Type* (newer controllers) — *Ticket Encryption Type* only as a fallback on older ones | DES and RC4 are refused for members. See [the krbtgt trap](verdict.md#the-krbtgt-trap) for why the ticket field alone is weak evidence. |
| **DES only** | `userAccountControl & 0x200000` | Forces exactly the cipher the group rejects. |
| **No AES in the etype mask** | `msDS-SupportedEncryptionTypes` set, non-zero, without AES128/AES256 | Same result, configured on the account itself. Absent or `0` means the domain default (AES) and is fine. |
| **Delegation configured** | `msDS-AllowedToDelegateTo`, UAC `0x1000000`, UAC `0x80000` | Members cannot delegate — constrained, protocol transition or unconstrained. Anything relying on it breaks. |
| **Wrong account type** | `objectClass` | Computer, service and **gMSA** accounts must never be members — a gMSA gets its own hint pointing at authentication policy silos instead. |
| **Disabled account** | `userAccountControl` | Enrolling a disabled admin achieves nothing — the fix is to take it out of the admin groups. |
| **Group present & effective** | Domain functional level, DC operating systems | Below 2012 R2 DFL there are client-side protections only; without the group there is nothing to join. |

The AD-derived checks come straight out of the directory, so unlike the log-based ones they are reliable even when auditing was switched off.

## Hardening hints — informational, never affect the verdict

- `adminCount=1` but not in Protected Users
- a user account carrying an **SPN** (a service account in disguise)
- *password never expires*, or a password over a year old
- *no Kerberos pre-auth* (AS-REP roastable)
- NTLM attempts that failed only as *no such user*
- Kerberos requests from a **client that offered no AES** (named by IP)
- a break-glass account that *is* enrolled
- an **already enrolled** account for which NTLM was still used or tried — probably turned away by the group; confirm with [`-Verify`](usage.md#post-enrolment-verification)

## Things no tool can clear you of

The report says so out loud, because none of it is readable from the directory:

- The TGT is fixed at **4 hours** and cannot be renewed — long-running scheduled tasks and batch jobs that rely on renewal stop.
- **No credential caching**, so **no offline sign-in**. An admin on a laptop away from a controller cannot log in.
- **CredSSP and WDigest** no longer hold the credential — tooling that delegates credentials breaks.
- Protections apply from the **next fresh logon**. An existing session or ticket hides the problem for hours.

The KDC's own **RC4 deprecation warnings** (System log, `Kerberos-Key-Distribution-Center` events 201–209) are read as well. They need no audit policy at all and are worth reading regardless of Protected Users.
