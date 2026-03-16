# Session Notes

## RMCP class byte must be 0x07 for all IPMI messages

The RMCP class byte for IPMI messages is 0x07 for **both** IPMI v1.5
and RMCP+ messages. The 0x80 bit in the class byte is the RMCP ACK
bit, NOT an RMCP+ indicator. The RMCP+ format is determined by
`auth_type = 0x06` in the session header. We were using class 0x87
which some BMCs tolerated (Supermicro) but HP iLO6 strictly rejects.

## HP iLO6 requires ASF Ping + Get Channel Auth Caps before RMCP+

The C `ipmitool` always sends an ASF Presence Ping and a Get Channel
Authentication Capabilities (as IPMI v1.5) before the RMCP+ Open
Session Request. HP iLO6 silently drops RMCP+ packets without this
priming sequence. Both are now sent as best-effort in the lanplus
connect flow.

## IPMI v1.5 MD5 auth code formula (no payload length byte)

The correct auth code formula for ALL messages (pre-session and
in-session) is:

    MD5(pw_pad16 || sid_LE || ipmi_msg || seq_LE || pw_pad16)

The payload length byte is NOT included. Confirmed against C
`ipmitool` 1.8.19 wire captures on a Supermicro BMC.

## Activate Session response layout

After completion code:

    [0]    Auth type
    [1..5] Session ID (LE, 4 bytes)
    [5..9] Initial message sequence number (LE, 4 bytes)
    [9]    Maximum privilege level (optional)

No privilege-level byte between auth type and session ID.

## iLO6 cipher suite support

- Cipher suite 17 (HMAC-SHA256): **rejected** by iLO6 with status
  0x11 ("no matching integrity payload") in Open Session Response
- Cipher suite 3 (HMAC-SHA1): accepted, but RAKP 4 ICV verification
  fails — **needs investigation**

## RAKP 4 ICV mismatch with cipher suite 3 on iLO6 — ROOT CAUSE FOUND

**Bug**: `derive_sik()` in `crypto/keys.rs` concatenates `Rm || Rc`
(BMC random first, console random second). The correct order per the
IPMI spec and C ipmitool is `Rc || Rm` (console random first, BMC
random second).

This was confirmed by replaying captured RAKP handshake packets in
`examples/rakp4_debug.rs`. With Rc||Rm order, the computed RAKP 4
ICV matches the BMC's value exactly.

**Fix**: Either swap the parameter order in the `derive_sik()` call
site (`transport/lanplus/mod.rs` line ~300), or swap the concatenation
order inside `derive_sik()` itself. The function signature documents
the parameters as `(rm, rc)` so the call site is passing them
correctly — the bug is in the function body.

Note: the C ipmitool's confusing comments label the fields "Rm" and
"Rc" backwards from the IPMI spec naming convention. In their code,
`console_rand` (which they place first) is Rc, and `bmc_rand` (placed
second) is Rm.
