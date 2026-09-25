# Setup & auditing

[← Documentation](README.md)

## Requirements

- **Windows PowerShell 5.1+** or **PowerShell 7+**. No RSAT and no `ActiveDirectory` module — the script uses `System.DirectoryServices` directly.
- Run on, or with line of sight to, a domain controller. **On a DC the session must be elevated**, since reading the local Security log requires it; the script refuses to continue otherwise.
- **WinRM** reachable on the controllers. The log reads run through a single fan-out `Invoke-Command` with a 20-second open timeout, so one wedged controller cannot stall the review. The operation timeout grows with `-Days` (15 minutes up to one hour).
- An account allowed to read the Security log on every domain controller in scope. Pass `-Credential` to use a separate tier-0 account from an admin workstation; from a machine outside the domain, also pass `-Domain`.
- Auditing enabled (below). Without it the tool reports what it could not see rather than pretending the result is complete.

## Audit policy

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

| Category → Subcategory | Value | Produces |
| --- | --- | --- |
| Logon/Logoff → **Audit Logon** | `Success` | **4624** — NTLM aimed at a controller |
| Account Logon → **Audit Kerberos Authentication Service** | `Success` | **4768** — DES/RC4 use and account key material |
| Account Logon → **Audit Credential Validation** | `Success` | **4776** — NTLM anywhere in the domain |

All three are checked **separately, per controller**, and each one gates only its own evidence. Partial coverage — *some* controllers audited, not all — is reported as a gap too, because an account that only ever authenticates against the unaudited one leaves no trace anywhere.

Apply and confirm:

```cmd
gpupdate /force
auditpol /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}
auditpol /get /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030}
auditpol /get /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030}
```

> [!IMPORTANT]
> Events are written **from the moment auditing is enabled — not retroactively.** Give a newly enabled policy a few weeks of normal operation before reading much into a quiet result.

## The two NTLM sources are not interchangeable

| Event | Subcategory | Sees |
| --- | --- | --- |
| **4624** | Audit Logon | NTLM aimed at a **controller itself** |
| **4776** | Credential Validation | NTLM **anywhere in the domain**, including against member servers and workstations |

`4776` is the broader of the two and the one that catches what actually breaks after enrolment. With only Credential Validation on, NTLM is still detected; you lose detail, not detection. Every coverage note names its own event and says what the other source still covers.

## On, off, and "could not tell"

| State | Meaning |
| --- | --- |
| **on** | `auditpol` reported a setting that records successes (`1` or `3`). |
| **off** | `auditpol` reported a setting that does not (`0` or `2`) — e.g. *Failure* only. Findings are genuinely missing. |
| **unknown** | The setting could not be read — no row returned, no numeric column, rights problem. **This is not "off"**. |

The environment section prints, per controller and subcategory, the state **and the literal text `auditpol` returned**:

```
dc01.corp.example.net: OS Windows Server 2022 Standard ok, 4768 v2.
   Logon (4624)                     off      auditpol says: Failure
   Kerberos AS (4768)               on       auditpol says: Success
   Credential Validation (4776)     on       auditpol says: Success and Failure
   read via: auditpol /backup
```

If a controller reports `unknown` for all three, the summary says so and points at rights rather than policy.

The parser locates the GUID column in `auditpol /backup` **by the shape of its value** and takes the setting as the last bare `0`–`3` field after it, so it depends on neither the header, the system language nor the column count (seven columns on some builds, five on others).
