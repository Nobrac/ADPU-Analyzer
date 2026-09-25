# Limitations

[← Documentation](README.md)

The tool flags **known blockers** from the evidence available; it cannot guarantee a sign-in will not break. Treat the recommendation as a well-informed starting point, not a promise.

- **Backward-looking evidence.** The log checks see only what the current Security logs still hold, and only on controllers that could be read. Log retention silently defines the observation window. `Plausible` and `Unknown` both mean "no proof either way".
- **A quiet account proves little.** If an account did not authenticate at all during the window, the clean result says nothing about how it authenticates when it does. This is called out per account.
- **4776 matches on the account name, not a SID.** The event carries no SID, so the match is by `sAMAccountName` within the account's own domain — unique there, but only there, which is why members from unreviewed domains are never scored. The name is recorded as the client typed it; the filter asks for the stored spelling plus its lower- and upper-case forms, so other mixed-case spellings may slip through. A name containing an apostrophe cannot be expressed in an Event XPath filter and is skipped with a note.
- **AES key evidence needs a recent controller.** *Available Keys* and the session-key type only appear on Server 2019+, or Server 2016 with the January 2025 cumulative update. Older controllers fall back to the `pwdLastSet` proxy and the ticket field, and the report says which ones.
- **Password age is a proxy.** "Password predates the group" approximates "the account has no AES keys". It is used only when nothing better was observed. The precise trigger is the domain functional level being raised, not the group's creation.
- **The `net group` fallback only reaches the local domain.** `net group … /domain` talks to the domain of the machine it runs on, so for accounts homed elsewhere the report prints a note instead of the command. The RSAT command always targets the account's home domain.
- **Blind spots it cannot see at all:** Kerberos time skew, external trusts that do not support AES, cached/offline logons (they never reach a controller), non-domain-joined clients, and applications that hardcode NTLM.
