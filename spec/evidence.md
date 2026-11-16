# Accord evidence and verdicts, version 1

Use protocol.json for the wire grammar and formation.md for consent rules.
A checker must report what the verified evidence proves. It must not guess a
terminal verdict when evidence is unknown or a deadline is still in the future.
Only synthetic data is in scope.

## Complete formation record

The checker trust configuration pins the session envelope digest, public catalog
bytes and digest, principal and role keys, and the named log operator. A message
cannot appoint its own trusted verifier. Each principal mandate binds the pinned
session setup digest. A valid signature proves attribution under these keys.
It does not prove that a statement is true.

A complete formation record has all of the following:

1. The signed SESSION event from the session start.
2. Every submitted raw event in a contiguous chain of signed ENTRY envelopes.
3. All keys and catalog entries needed to check authority and message meaning.
4. A signed CHECKPOINT that binds the session, start, cutoff, last sequence and
   last entry digest, with `formation_complete: true`.
5. An explicit trust basis for the operator's exhaustive record and logical time.

ENTRY sequence starts at 1. Its first `previous` is null. Each next `previous` is
the SHA-256 digest of the complete canonical signed preceding ENTRY. It wraps one
raw event as unpadded base64url. This wrapper can retain a rejected event, including
bad JSON, without treating it as a valid protocol message. Do not nest ENTRY or
CHECKPOINT as events. Event and wrapper byte limits apply before parsing.

The operator signs nondecreasing ticks. A valid event has its ENTRY tick. Sequence
breaks ties. CHECKPOINT covers every event from start through cutoff inclusive.
No event at or below an issued cutoff may be appended later. Its last sequence
must match the supplied chain. Verify all links and both operator signatures and
event signatures. A gap, changed link, inconsistent checkpoint, unknown tick,
unavailable key or incomplete prefix gives `null` with `unknown`.

A complete prefix is required even when both ACCEPT messages are present. It must
exclude an omitted prior revocation, revision or referee decision. For a terminal
absence verdict, the cutoff must reach the SESSION expiry. Revision expiry cannot
extend that bound. A complete prefix before expiry can give `pending`, with that
expiry as `next_deadline`. `formation: absent` then means no formation in the
verified prefix. It does not mean formation can never occur.

Trust is explicit: the named operator observes every submission to the session
and makes a truthful completeness claim. Principals do not share trusted wall
clocks. Signed checkpoints expose operator claims for audit but do not make them
true. An operator can omit events or state false ticks. This specification assumes
that it does neither. A deployment needs a separate trust review and a route to
obtain complete records. A local Boolean completeness flag is not wire evidence.

## Trusted observer coverage

Each proposal names an observer and public predicate for each prerequisite and
performance obligation. Verify that these match the pinned catalog. An unrelated
observer or a valid receipt for another session, proposal or obligation cannot
prove the claim here. Observer trust must cover both truth and the stated scope.

An OUTCOME receipt binds session, proposal digest, obligation ID, debtor, action,
quantity, completion tick, status and signer. The observer must be the one named
for that obligation. Completion must be after formation and at or before the
receipt tick. Receipt issue time may be after the deadline. The completion time
determines whether delivery was timely.

For this bounded version, each obligation has one terminal observer snapshot:

| Snapshot | Use |
|---|---|
| done | Total delivered quantity and completion tick. Full quantity by the deadline proves performance. Full quantity after the deadline proves failure of the deadline obligation. |
| missed | Final insufficient delivery. Issue and completion ticks must be at or after the deadline. This is a trusted failure claim. |
| partial | A cumulative quantity observation. It proves neither full performance nor the absence of later delivery. |

A COVERAGE certificate can prove absence or insufficient performance only if the
proposal-named observer has exclusive, exhaustive observation from formation
through at least the obligation deadline. It binds the same session, digest and
obligation, the interval, and total timely quantity. `complete` and `exclusive`
must both be true, and the trust configuration must support those claims.
The cutoff cannot exceed the certificate tick. A start after formation leaves a
gap. The observer's signed statement must attest that no other delivery route is
possible under the predicate. Missing receipt bytes alone are not that statement.

Formation-log completeness does not imply performance-observer completeness.
A partial snapshot plus valid complete coverage can prove insufficient delivery.
A partial snapshot alone gives unknown after the deadline. Missing performance
receipts also give unknown after the deadline. Before an unresolved deadline,
with a valid evidence prefix and no conflict, the result is pending.

Distinct valid terminal snapshots for one obligation conflict. A duplicate of the
same signed snapshot is harmless. Inconsistent coverage or a contradiction between
coverage and a snapshot makes that obligation unknown. Do not select the more
favourable receipt or sum competing snapshots. Incremental receipt updates and
amendments are outside this version. A separate obligation with independent trusted
failure proof can still decide breached.

## Replay, rejection and collisions

Use `(session, id)` as the message-ID key for protocol events. Exact canonical
signed-byte replay is idempotent. It creates no second consent, delivery or response
turn. Check replay identity before requiring a fresh event tick. A later wrapper
may retain replay bytes for audit, but it has no new protocol effect.

Different authenticated bytes for one message-ID key give `null` with `unknown`.
Do not choose the first, last or most favourable copy. This rule applies even if
the differing event would later fail a grammar or scope rule. An invalid signature
cannot manufacture an authenticated collision. Keep the conflicting records as
evidence. Log sequence or checkpoint contradictions also give unknown.

Reject foreign session events, invalid signatures, extra fields, invalid types,
wrong authority and out-of-scope mandates. Rejection is not missing verification:
a verifier that cannot run gives unknown. A complete record with a known invalid
ACCEPT can prove never formed after expiry. A rejected utility payload supplies
no consent but does not cancel independent valid ACCEPT messages.

## Decision table and result API

Return all fields listed in `checker.required_output_fields`. `verdict` is a JSON
string or JSON null. The string `"null"` is not valid. Only honoured, breached and
never formed are terminal verdicts. Unknown and pending are evidence states.

Apply this order. Resolve authenticated message collisions and formation-record
ambiguity first. A performance failure cannot repair uncertain formation.

| Verified condition | verdict | evidence_status | formation |
|---|---|---|---|
| Formation record missing, incomplete through the evaluation cutoff, contradictory, or unverifiable | null | unknown | unknown |
| No formation in a complete prefix; session expiry is still in the future | null | pending | absent |
| No valid formation in a complete record through session expiry | never formed | complete | absent |
| Valid formation and at least one independent trusted failure proof | breached | complete | formed |
| Valid formation and every obligation has trusted full timely performance proof | honoured | complete | formed |
| Valid formation, no proved breach, but a due obligation lacks evidence or has conflicting evidence | null | unknown | formed |
| Valid formation, no proved breach or conflict, and every unresolved obligation has a future deadline | null | pending | formed |

A performance conflict gives unknown even before the deadline, unless an independent
breach decides. Unknown evidence takes priority over mere waiting. When pending,
return session expiry or the earliest unresolved obligation deadline as
`next_deadline`. Otherwise that field is null. `failed_obligations` is empty except
for breached. For breached, give each proved failed obligation and its debtor.

`complete` means the evidence is sufficient for this decision. An independent
proved breach can decide the result while another obligation remains unknown.
It does not assert that every receipt is present. Missing logs cannot mean never
formed. Missing receipts cannot mean breached. Pending cannot become a terminal
verdict merely because the API requires an answer.

## Research worked examples

These 39 case IDs refer to the measured synthetic research transcripts. Their
expected semantic results are normative examples. The old HMAC envelopes and
local completeness flags must be replaced by the signed wire evidence above in
the reference checker fixtures. No fixture file is included in this specification.

The base case has proposal tick 1, ACCEPT ticks 3 and 4, formation expiry 10,
mandate expiry 11, performance deadline 20 and evaluation cutoff 30. Each debtor
owes one abstract unit. Both done receipts show completion at tick 15. Changes
below describe each case relative to that base. Complete formation and trusted
observation are explicit example assumptions, not claims about a live service.

| Case ID | Changed evidence and reason | Expected verdict | Evidence status |
|---|---|---|---|
| 01_honoured_direct | Both agents accept and both obligations have timely full receipts. | honoured | complete |
| 02_missing_signature | One ACCEPT lacks its signature. It cannot supply consent. | never formed | complete |
| 03_missing_mandate | One agent has no mandate in the complete record. | never formed | complete |
| 04_scope_mismatch | B's mandate allows d0 but the proposal uses d1. | never formed | complete |
| 05_expiry_at_boundary | B accepts at proposal expiry 10. Expiry is exclusive. | never formed | complete |
| 06_acceptance_expiry | A's ACCEPT expires at 4, when B accepts. | never formed | complete |
| 07_first_mandate_expires | A's mandate expires at 4, when B accepts. Recheck it. | never formed | complete |
| 08_stale_acceptance | Revision 2 replaces revision 1. Both accept the old digest. | never formed | complete |
| 09_conflicting_acceptance_revisions | A accepts revision 2; B accepts revision 1. | never formed | complete |
| 10_equivocation_same_revision | A signs two distinct revision 1 proposals before formation. | never formed | complete |
| 11_conditional_without_proof | ready is required. CONDITIONAL and ACCEPT cannot replace its proof. | never formed | complete |
| 12_condition_true_then_fresh_accepts | ready is proved at 2; both ACCEPT messages follow it. | honoured | complete |
| 13_late_condition_no_auto_consent | ready is proved at 5 after the ACCEPT messages. No fresh consent follows. | never formed | complete |
| 14_revoke_acceptance_before_formation | A revokes its ACCEPT before B accepts. | never formed | complete |
| 15_revoke_mandate_before_formation | A's principal revokes its mandate before B accepts. | never formed | complete |
| 16_revoke_after_formation | A revokes after formation. The obligations remain and are met. | honoured | complete |
| 17_exact_replay_idempotent | A's exact ACCEPT is replayed. It has no extra effect. | honoured | complete |
| 18_cross_session_replay | B's acceptance names a different session. | never formed | complete |
| 19_authenticated_message_id_collision | Two signed aA events use one ID but different expiry bytes. | null | unknown |
| 20_partial_closed_record | B delivers zero. Exclusive complete observer coverage reaches the deadline. | breached | complete |
| 21_partial_open_record | B's zero partial receipt lacks complete observer coverage. | null | unknown |
| 22_missing_performance_receipt | B's receipt is missing and coverage is not complete. | null | unknown |
| 23_closed_observer_no_delivery | B has no delivery receipt; exclusive complete coverage proves no delivery. | breached | complete |
| 24_signed_failure | The named observer attests B's final missed obligation after its deadline. | breached | complete |
| 25_late_delivery | B's done receipt reports completion at 21, after deadline 20. | breached | complete |
| 26_missing_formation_log | Formation completeness is absent, despite apparent ACCEPT messages. | null | unknown |
| 27_unavailable_verifier | Signature or mandate verification cannot run. | null | unknown |
| 28_referee_absent | Both intents exist in referee mode, but no FORM arrives. No direct fallback. | never formed | complete |
| 29_referee_certificate | Named referee issues valid FORM at 5; performance is timely. | honoured | complete |
| 30_referee_late_certificate | FORM arrives at expiry 10. It cannot form the deal. | never formed | complete |
| 31_acceptable_is_not_consent | Only ACCEPTABLE is sent. No ACCEPT messages exist. | never formed | complete |
| 32_preference_payload_rejected | Reject the utility payload. Independent valid ACCEPT messages and receipts remain. | honoured | complete |
| 33_ask_human_pauses | ASK_HUMAN pauses consent. No new mandates follow. | never formed | complete |
| 34_conflicting_observer_evidence | The observer signs done and missed for B. No other failure is proved. | null | unknown |
| 35_performance_pending | Cutoff is 8. The deal formed, but deadline 20 is still in the future. | null | pending |
| 36_formation_pending | Cutoff is 8. Only A has accepted; session expiry 10 is still in the future. | null | pending |
| 37_breach_dominates_other_unknown | A has a proved missed obligation. B's receipt is missing. | breached | complete |
| 38_tampered_signed_field | B's expiry changes to 99 without a new signature. Reject the ACCEPT. | never formed | complete |
| 39_fresh_revision_forms | Both agents freshly accept revision 2 and its obligations are met. | honoured | complete |

These examples do not test production cryptography, key storage, log honesty,
observer truth, preference secrecy, legal effect or fair exchange. The reference
checker must also test canonical encoding, byte limits, signatures and checkpoint
gaps against the normative wire grammar.
