# Accord formation, version 1

This document and evidence.md define the state rules. protocol.json defines the
closed wire grammar. All three files are normative. The pull request has two
DECISION items. Merge approves the null-result API and the time and log trust
model described here. This is a specification for a bounded synthetic protocol.

A deal is **formed** when the rule for its signed formation mode succeeds.
Formation creates protocol obligations. It does not execute an external action.
It does not prove legal enforceability.

## Encoding and signatures

Use Ed25519, the PureEdDSA variant in [RFC 8032, section 5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1).
Sign the UTF-8 bytes of [RFC 8785 canonical JSON](https://www.rfc-editor.org/rfc/rfc8785)
for the complete envelope without its top-level `signature` field. Do not prehash
the input. Encode the raw signature as unpadded base64url. Its length is 86 ASCII
characters. Use the pinned public key for the signed `signer` ID.

This choice lets a reader verify a signature without a shared signing secret.
Canonical JSON gives each reader the same bytes. Version, session, message ID,
signer, kind and tick are inside the signed envelope. Reject duplicate keys,
unknown fields, noncanonical bytes and invalid types before use. A missing or
invalid signature is invalid consent. An unavailable verifier is unknown evidence.

The research cases use HMAC-SHA256 with public synthetic keys. HMAC is not this
specification. The checker must regenerate the wire fixtures with Ed25519 and the
new envelope fields. It must preserve the research case IDs and expected results.
No research signature or digest is a normative wire example.

## Session and proposal identity

Before messages can supply authority, pin the session, catalog and key registry
in the checker trust configuration. The named log operator signs `SESSION`.
Its digest binds the nonce, ordered principals A and B, their agents, fixed proposer
A, catalog digest, log operator, optional referee and formation interval. Both
principal mandates name that setup digest. An untrusted session message cannot
install a trusted key or change the catalog. Do not reuse a session ID or nonce.

A session has one `proposal_id` and one revision chain. A proposes revision 1 with
`previous: null`. Each later revision increments the number by one and names the
previous proposal digest. The digest is lowercase hexadecimal SHA-256 of the
unsigned canonical PROPOSE envelope. It covers all fields listed in
`proposal.digest_fields` in protocol.json. This includes the message identity,
issue tick, terms, conditions, obligations, expiry, mode and referee.

Each new valid revision clears all pending acceptances. Consent to an old digest
cannot carry to the new digest. Two distinct valid proposal digests at one revision
before formation block that session. Use a new session to recover. A malformed
proposal does not replace the current revision. Once formed, a later proposal
cannot change the deal. Amendment and bilateral cancellation are outside version 1.

Terms come from the pinned public catalog. The proposal lists each obligation's
ID, debtor principal, action, quantity, deadline, observer and predicate. These
values must match the catalog. An obligation deadline is after formation expiry.
Full performance completed at the deadline is timely. Completion after it is late.

## Responses and consent

The seven RESPONSE words never bind, even when signed.

| Word | Effect |
|---|---|
| VETO | Reject this revision. It does not revoke earlier consent. |
| ACCEPTABLE | Report that a local check passed. It supplies no consent. |
| PREFERRED | Compare this revision with one named public revision. It supplies no consent. |
| COUNTER | Refer to one public counterproposal. It supplies no consent or revision change. |
| CONDITIONAL | Name objective conditions already in the proposal. It supplies no consent. |
| DEFER | Name a bounded retry round. It does not extend expiry. |
| ASK_HUMAN | Clear pending consent and pause automated consent. Each principal must issue a fresh mandate before it resumes. |

Only a separate signed `ACCEPT` supplies consent. It names the exact current
proposal digest, the accepter's mandate and its own expiry. Each agent must issue
its own ACCEPT. A proposal signature does not count as one of these acceptances.
No response, silence, condition proof or inferred preference can replace ACCEPT.
A rejected response does not erase separate valid consent.

Only objective prerequisites in the public catalog are allowed. Each condition
names an observer and a predicate. The observer must sign a true certificate for
this exact session and proposal digest before either acceptance. The prerequisite
must be irreversible. A false or unknown condition cannot enable consent.
Conflicting certificates require a new session. Proof after ACCEPT does not
activate that ACCEPT. Both parties must issue fresh ACCEPT messages after proof.
A change to terms or conditions needs a new revision and fresh acceptances.

RESPONSE confidence is always `unspecified`. Conditions and response expiry must
match the proposal constraints. Reject all extra fields and raw preference data.
The 512-byte response limit includes the signature. Choices, timing, silence and
repeated proposals can still reveal preferences. This grammar proves no secrecy.

## Mandates and intervals

Each principal signs a mandate for its own agent and session. It names the setup
digest, terms IDs, consent or performance permission, allowed obligation actions,
maximum quantity, start, expiry and revocation ID. Check each debtor's total
quantity against that principal's mandate. Empty scope grants no authority.
An agent cannot delegate its authority in this version. An acceptance mandate
does not execute or authorise a separate performance effect.

At formation, both mandates must be present, valid, in scope and unrevoked.
Recheck the first accepter's mandate and ACCEPT too. Earlier validity is not enough.

All validity intervals include their start and exclude their expiry:

    start <= formation_tick < expiry

A proposal and ACCEPT start at their signed tick. A mandate starts at `start`.
Proposal expiry cannot exceed session expiry. ACCEPT expiry cannot exceed proposal
expiry. Formation at any applicable expiry fails. Performance uses its separate
deadline rule above.

## Log order and revocation

The named log operator assigns nondecreasing logical ticks and a signed sequence.
A valid event has the tick of its enclosing ENTRY. A sender must obtain an operator
tick before it signs. Sequence resolves events with the same tick. Principals do
not trust each other's wall clocks. Logical ticks do not establish elapsed time.
The trust and completeness rules are in evidence.md.

A principal can sign REVOKE for its own mandate revocation ID. An agent can sign
REVOKE for its own exact pending ACCEPT message ID. The target must precede REVOKE.
An unauthorised revocation has no effect. Revocation cannot be undone. A fresh
acceptance or mandate uses a new ID.

A revocation ordered before formation cancels the target authority or consent.
A revocation ordered after formation cannot erase the deal or excuse failure.
Thus a REVOKE before the second acceptance prevents direct formation. The same
REVOKE after the second acceptance does not cancel it. In referee mode the relevant
boundary is FORM. Network arrival order outside this log cannot decide the race.

## Formation modes

In direct mode, the second valid ACCEPT forms the deal at its sequence and tick.
At that position, both agents must have live acceptances for the same current
digest. Check all signatures, scopes, conditions, intervals, revocations and pause
state again. Form at most once. Evidence.md still requires a complete trusted log
prefix, since an omitted earlier revocation can change this conclusion.

In referee mode, both ACCEPT messages are intents. They do not form a deal.
The session-named referee must sign FORM for the current digest and the two exact
ACCEPT IDs. At FORM, recheck every direct-mode requirement and interval. The FORM
must occur before all relevant expiries. An absent or late referee cannot switch
the session to direct mode.

The referee may instead sign ABORT before formation and session expiry. It then
closes formation for that session. The referee must store one decision durably
and make it recoverable. Conflicting signed decisions give unknown evidence.
Version 1 validates supplied certificates. It does not specify a complete network
abort/resolve service.

## Fair exchange limit

Direct mode gives no strong fair-exchange guarantee against abort or unbounded
message delay. One party can obtain evidence before the other party obtains it.
Two signatures alone do not ensure that both parties obtain usable evidence.

The primary research source is Vogt, Pagnia and Gartner,
[Modular Fair Exchange Protocols for Electronic Commerce](https://www.acsac.org/1999/papers/wed-a-1030-vogt.pdf),
1999, pages 1 to 3. It distinguishes fairness levels and explains trusted-party
and optimistic recovery designs. The limit stated here applies to this direct
protocol under abort and delay; it is not a claim about every special exchange model.

A fair referee design needs mutual trust, no collusion, durable single-decision
storage, verified authority, eventual access to the result and a defined
abort/resolve protocol. These are assumptions and further design work. A valid
FORM certificate alone is not a fair-exchange proof. A trusted log is an order
service; it is not automatically a fair-exchange referee. External performance
has separate failure risks.
