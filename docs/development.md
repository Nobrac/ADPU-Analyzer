# Development

[← Documentation](README.md)

## Repository layout

```
README.md                     project front page
LICENSE                       MIT
ADPU-Analyzer.ps1             the whole tool (single file, read-only)
docs/                         this documentation
tests/ADPU-Analyzer.Tests.ps1 unit tests - no AD, no Pester, runs on Linux too
screenshots/                  image used in the README
```

## Tests

The scoring engine is a pure function over plain objects, so the tests run the whole decision table on synthetic input — including a "kitchen sink" topology that renders the console, HTML and JSON reports with every account, controller and domain state at once. The helpers inside the remote collector (etype and key parsing, the `auditpol` CSV parser) are lifted out of its source text and tested on their own. The same tests also run under `Set-StrictMode -Version 3`, which turns any reference to a property that does not exist into a failure.

```powershell
pwsh -File tests/ADPU-Analyzer.Tests.ps1
$env:ADPU_STRICT = 1; pwsh -File tests/ADPU-Analyzer.Tests.ps1
```

The exit code is the number of failed checks.

The part that runs on the controllers (event log and `auditpol` reads) cannot be exercised without Active Directory; changes there need a run against a real domain.

## Encoding

`ADPU-Analyzer.ps1` is saved as **UTF-8 with BOM**. Windows PowerShell 5.1 reads a file without BOM as ANSI, which garbles the localised `auditpol` strings the script matches on (e.g. *Keine Überwachung*). Keep the BOM when editing.
