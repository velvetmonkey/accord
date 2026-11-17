"""Tests for the Accord version 1 reference checker.

tests/fixtures/transcripts.jsonl holds one transcript per line with its
expected result, stored before evaluation. The cases 01 to 39 are the
research worked examples in spec/evidence.md, regenerated with Ed25519 and
the spec encoding. Cases 40 to 45 add wire-level checks. Case 46 checks cross-revision receipt collisions.

The fixture is generated from fixed synthetic seeds by build_cases() below.
Ed25519 signatures are deterministic, so test_fixture_is_reproducible proves
that the committed bytes come from this generator. To regenerate:

    python3 tests/test_checker.py --write
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from accord import checker as c  # noqa: E402
from accord import messages as m  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "transcripts.jsonl"

# ---------------------------------------------------------------------------
# Synthetic keys from fixed test seeds. No key material leaves this file.

ROLES = ["log", "pA", "pB", "aA", "aB", "ref", "obs", "cobs", "mallory"]


def _private(role: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"accord-synthetic-test-seed/" + role.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


PRIVATE = {r: _private(r) for r in ROLES}
PUBLIC = {
    r: m.b64url_encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)) for r, k in PRIVATE.items()
}

CATALOG = {
    "terms": ["t1"],
    "conditions": {"ready": {"observer": "cobs", "predicate": "p_ready"}},
    "obligations": {
        "oA": {"debtor": "pA", "action": "d0", "quantity": 1, "deadline": 20, "observer": "obs", "predicate": "p_d0"},
        "oB": {"debtor": "pB", "action": "d1", "quantity": 1, "deadline": 20, "observer": "obs", "predicate": "p_d1"},
    },
}
OBLIGATIONS = [{"id": oid, **CATALOG["obligations"][oid]} for oid in ("oA", "oB")]
CONDITIONS = [{"id": "ready", **CATALOG["conditions"]["ready"]}]


def sign(fields: dict, key_role: str | None = None) -> dict:
    msg = {"version": 1, "session": "s1", **fields}
    sig = PRIVATE[key_role or msg["signer"]].sign(m.signed_bytes(msg))
    return {**msg, "signature": m.b64url_encode(sig)}


def wire(msg: dict) -> bytes:
    return m.canonical(msg)


class Scenario:
    """Build one transcript: SESSION, ordered events, checkpoint and receipts."""

    def __init__(self, evaluation_tick: int = 30, cutoff: int = 30) -> None:
        self.evaluation_tick = evaluation_tick
        self.cutoff = cutoff
        self.events: list[tuple[int, bytes]] = []
        self.receipts: list[bytes] = []
        self.keys = dict(PUBLIC)
        del self.keys["mallory"]  # Not a pinned role.
        self.with_checkpoint = True
        self.drop_entry: int | None = None
        self.alter_entry: int | None = None
        self.session = sign(
            {
                "id": "setup",
                "signer": "log",
                "kind": "SESSION",
                "tick": 0,
                "nonce": "n1",
                "principals": ["pA", "pB"],
                "agents": ["aA", "aB"],
                "proposer": "aA",
                "log_operator": "log",
                "referee": "ref",
                "catalog_digest": m.sha256_hex(m.canonical(CATALOG)),
                "start": 0,
                "expiry": 10,
            }
        )
        self.setup_digest = m.event_digest(self.session)
        self.events.append((0, wire(self.session)))

    # -- events ----------------------------------------------------------

    def add(self, msg_or_raw, tick: int | None = None) -> dict | bytes:
        raw = msg_or_raw if isinstance(msg_or_raw, bytes) else wire(msg_or_raw)
        if tick is None:
            tick = msg_or_raw["tick"]
        self.events.append((tick, raw))
        return msg_or_raw

    def mandate(self, principal: str, ident: str, rid: str, tick: int = 0, **over) -> dict:
        agent = {"pA": "aA", "pB": "aB"}[principal]
        action = {"pA": "d0", "pB": "d1"}[principal]
        fields = {
            "id": ident,
            "signer": principal,
            "kind": "MANDATE",
            "tick": tick,
            "principal": principal,
            "agent": agent,
            "setup_digest": self.setup_digest,
            "terms": ["t1"],
            "action": "accept",
            "actions": [action],
            "max_quantity": 1,
            "start": 0,
            "expiry": 11,
            "revocation_id": rid,
        }
        fields.update(over)
        return sign(fields)

    def mandates(self, **over_b) -> None:
        self.add(self.mandate("pA", "mA", "rA"))
        self.add(self.mandate("pB", "mB", "rB", **over_b))

    def propose(self, ident: str = "prop1", tick: int = 1, revision: int = 1, previous=None, **over) -> dict:
        fields = {
            "id": ident,
            "signer": "aA",
            "kind": "PROPOSE",
            "tick": tick,
            "proposal_id": "deal1",
            "revision": revision,
            "previous": previous,
            "terms": "t1",
            "conditions": [],
            "obligations": OBLIGATIONS,
            "expiry": 10,
            "mode": "direct",
            "referee": None,
        }
        fields.update(over)
        return sign(fields)

    def accept(self, agent: str, digest: str, tick: int, ident: str | None = None, **over) -> dict:
        fields = {
            "id": ident or ("accA" if agent == "aA" else "accB"),
            "signer": agent,
            "kind": "ACCEPT",
            "tick": tick,
            "digest": digest,
            "mandate": "mA" if agent == "aA" else "mB",
            "expiry": 10,
        }
        key_role = over.pop("key_role", None)
        fields.update(over)
        return sign(fields, key_role)

    def response(self, agent: str, ident: str, digest: str, word: str, tick: int, **opt) -> dict:
        fields = {
            "id": ident,
            "signer": agent,
            "kind": "RESPONSE",
            "tick": tick,
            "digest": digest,
            "response": word,
            "expiry": 10,
            "confidence": "unspecified",
        }
        fields.update(opt)
        return sign(fields)

    def revoke(self, signer: str, ident: str, target_kind: str, target: str, tick: int) -> dict:
        return sign(
            {"id": ident, "signer": signer, "kind": "REVOKE", "tick": tick, "target_kind": target_kind, "target": target}
        )

    def condition(self, digest: str, tick: int, value: bool = True, ident: str = "condready") -> dict:
        return sign(
            {
                "id": ident,
                "signer": "cobs",
                "kind": "CONDITION",
                "tick": tick,
                "digest": digest,
                "condition": "ready",
                "value": value,
            }
        )

    def form(self, digest: str, tick: int) -> dict:
        return sign(
            {"id": "form1", "signer": "ref", "kind": "FORM", "tick": tick, "digest": digest, "accept_ids": ["accA", "accB"]}
        )

    # -- receipts --------------------------------------------------------

    def outcome(
        self, digest: str, obligation: str, status: str, quantity: int, completed: int, tick: int, ident: str | None = None
    ) -> None:
        obl = CATALOG["obligations"][obligation]
        msg = sign(
            {
                "id": ident or f"out{obligation}",
                "signer": "obs",
                "kind": "OUTCOME",
                "tick": tick,
                "digest": digest,
                "obligation": obligation,
                "debtor": obl["debtor"],
                "action": obl["action"],
                "quantity": quantity,
                "completed_tick": completed,
                "status": status,
            }
        )
        self.receipts.append(wire(msg))

    def coverage(self, digest: str, obligation: str, start: int, cutoff: int, quantity: int, tick: int) -> None:
        msg = sign(
            {
                "id": f"cov{obligation}",
                "signer": "obs",
                "kind": "COVERAGE",
                "tick": tick,
                "digest": digest,
                "obligation": obligation,
                "start": start,
                "cutoff": cutoff,
                "quantity": quantity,
                "complete": True,
                "exclusive": True,
            }
        )
        self.receipts.append(wire(msg))

    def done(self, digest: str, *obligations: str, completed: int = 15) -> None:
        for oid in obligations or ("oA", "oB"):
            self.outcome(digest, oid, "done", 1, completed, completed + 1)

    # -- transcript ------------------------------------------------------

    def transcript(self) -> dict:
        entries: list[bytes] = []
        previous = None
        for seq, (tick, raw) in enumerate(self.events, start=1):
            entry = sign(
                {
                    "id": f"e{seq}",
                    "signer": "log",
                    "kind": "ENTRY",
                    "tick": tick,
                    "sequence": seq,
                    "previous": previous,
                    "event_bytes": m.b64url_encode(raw),
                }
            )
            previous = m.event_digest(entry)
            entries.append(wire(entry))
        last_tick = self.events[-1][0]
        checkpoint = sign(
            {
                "id": "cp",
                "signer": "log",
                "kind": "CHECKPOINT",
                "tick": max(self.cutoff, last_tick),
                "last_sequence": len(entries),
                "last_entry_digest": previous,
                "start": 0,
                "cutoff": self.cutoff,
                "formation_complete": True,
            }
        )
        if self.alter_entry is not None:
            entries[self.alter_entry] = alter_event_bytes(entries[self.alter_entry])
        if self.drop_entry is not None:
            del entries[self.drop_entry]
        return {
            "trust": {
                "session": "s1",
                "session_digest": self.setup_digest,
                "log_operator": "log",
                "keys": self.keys,
                "catalog": CATALOG,
                "coverage_observers": ["obs"],
            },
            "evaluation_tick": self.evaluation_tick,
            "log": [m.b64url_encode(e) for e in entries],
            "checkpoint": m.b64url_encode(wire(checkpoint)) if self.with_checkpoint else None,
            "receipts": [m.b64url_encode(r) for r in self.receipts],
        }


def alter_event_bytes(entry_raw: bytes) -> bytes:
    """Change one character inside the signed event_bytes of a canonical ENTRY."""
    entry = json.loads(entry_raw)
    text = entry["event_bytes"]
    middle = len(text) // 2
    entry["event_bytes"] = text[:middle] + ("A" if text[middle] != "A" else "B") + text[middle + 1 :]
    return m.canonical(entry)


def alter_signed_byte(raw: bytes, old: bytes, new: bytes) -> bytes:
    """Replace one signed byte in canonical wire bytes; the signature stays the same."""
    assert raw.count(old) == 1 and len(old) == len(new)
    return raw.replace(old, new)


def digest_of(msg: dict) -> str:
    return m.proposal_digest(msg)


# ---------------------------------------------------------------------------
# Expected results


def honoured() -> dict:
    return c.result("honoured", "complete", "formed")


def never_formed() -> dict:
    return c.result("never formed", "complete", "absent")


def unknown_formation() -> dict:
    return c.result(None, "unknown", "unknown")


def unknown_performance() -> dict:
    return c.result(None, "unknown", "formed")


def breached(oid: str) -> dict:
    debtor = CATALOG["obligations"][oid]["debtor"]
    return c.result("breached", "complete", "formed", [{"id": oid, "debtor": debtor}])


# ---------------------------------------------------------------------------
# Cases. The base case: proposal tick 1, ACCEPT ticks 3 and 4, formation
# expiry 10, mandate expiry 11, deadline 20, evaluation cutoff 30, one unit
# per debtor, both done receipts complete at tick 15.


def base(s: Scenario | None = None, **propose_over) -> tuple[Scenario, str]:
    s = s or Scenario()
    s.mandates()
    p = s.add(s.propose(**propose_over))
    return s, digest_of(p)


def formed_base(s: Scenario | None = None) -> tuple[Scenario, str]:
    s, d = base(s)
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    return s, d


def case_01():
    s, d = formed_base()
    s.done(d)
    return s, honoured()


def case_02():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    unsigned = m.unsigned(s.accept("aB", d, 4))
    s.add(wire(unsigned), 4)
    s.done(d)
    return s, never_formed()


def case_03():
    s = Scenario()
    s.add(s.mandate("pB", "mB", "rB"))
    p = s.add(s.propose())
    d = digest_of(p)
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_04():
    s = Scenario()
    s.mandates(actions=["d0"])
    p = s.add(s.propose())
    d = digest_of(p)
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_05():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 10))
    s.done(d)
    return s, never_formed()


def case_06():
    s, d = base()
    s.add(s.accept("aA", d, 3, expiry=4))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_07():
    s = Scenario()
    s.add(s.mandate("pA", "mA", "rA", expiry=4))
    s.add(s.mandate("pB", "mB", "rB"))
    p = s.add(s.propose())
    d = digest_of(p)
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_08():
    s, d1 = base()
    p2 = s.add(s.propose("prop2", 2, 2, d1))
    s.add(s.accept("aA", d1, 3))
    s.add(s.accept("aB", d1, 4))
    s.done(d1)
    for oid in ("oA", "oB"):
        s.outcome(digest_of(p2), oid, "done", 1, 16, 17, ident=f"rev2out{oid}")
    return s, never_formed()


def case_09():
    s, d1 = base()
    d2 = digest_of(s.add(s.propose("prop2", 2, 2, d1)))
    s.add(s.accept("aA", d2, 3))
    s.add(s.accept("aB", d1, 4))
    s.done(d2)
    return s, never_formed()


def case_10():
    s, d1 = base()
    s.add(s.propose("prop1b", 2, expiry=9))
    s.add(s.accept("aA", d1, 3))
    s.add(s.accept("aB", d1, 4))
    s.done(d1)
    return s, never_formed()


def case_11():
    s, d = base(conditions=CONDITIONS)
    s.add(s.response("aB", "resp1", d, "CONDITIONAL", 2, condition_ids=["ready"]))
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_12():
    s, d = base(conditions=CONDITIONS)
    s.add(s.condition(d, 2))
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, honoured()


def case_13():
    s, d = base(conditions=CONDITIONS)
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.add(s.condition(d, 5))
    s.done(d)
    return s, never_formed()


def case_14():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.revoke("aA", "revA", "ACCEPT", "accA", 4))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_15():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.revoke("pA", "revA", "MANDATE", "rA", 4))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_16():
    s, d = formed_base()
    s.add(s.revoke("aA", "revA", "ACCEPT", "accA", 5))
    s.done(d)
    return s, honoured()


def case_17():
    s, d = base()
    acc_a = s.add(s.accept("aA", d, 3))
    s.add(wire(acc_a), 4)  # exact replay in a later ENTRY
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, honoured()


def case_18():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4, session="s2"))
    s.done(d)
    return s, never_formed()


def case_19():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aA", d, 4, expiry=9))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, unknown_formation()


def case_20():
    s, d = formed_base()
    s.done(d, "oA")
    s.outcome(d, "oB", "partial", 0, 20, 20)
    s.coverage(d, "oB", 4, 20, 0, 20)
    return s, breached("oB")


def case_21():
    s, d = formed_base()
    s.done(d, "oA")
    s.outcome(d, "oB", "partial", 0, 20, 20)
    return s, unknown_performance()


def case_22():
    s, d = formed_base()
    s.done(d, "oA")
    s.coverage(d, "oB", 4, 15, 0, 15)  # does not reach the deadline
    return s, unknown_performance()


def case_23():
    s, d = formed_base()
    s.done(d, "oA")
    s.coverage(d, "oB", 4, 20, 0, 20)
    return s, breached("oB")


def case_24():
    s, d = formed_base()
    s.done(d, "oA")
    s.outcome(d, "oB", "missed", 0, 20, 21)
    return s, breached("oB")


def case_25():
    s, d = formed_base()
    s.done(d, "oA")
    s.outcome(d, "oB", "done", 1, 21, 22)
    return s, breached("oB")


def case_26():
    s, d = formed_base()
    s.done(d)
    s.with_checkpoint = False
    return s, unknown_formation()


def case_27():
    s, d = formed_base()
    s.done(d)
    del s.keys["aB"]
    return s, unknown_formation()


def referee_base() -> tuple[Scenario, str]:
    s, d = base(mode="referee", referee="ref")
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    return s, d


def case_28():
    s, d = referee_base()
    s.done(d)
    return s, never_formed()


def case_29():
    s, d = referee_base()
    s.add(s.form(d, 5))
    s.done(d)
    return s, honoured()


def case_30():
    s, d = referee_base()
    s.add(s.form(d, 10))
    s.done(d)
    return s, never_formed()


def case_31():
    s, d = base()
    s.add(s.response("aB", "resp1", d, "ACCEPTABLE", 3))
    return s, never_formed()


def case_32():
    s, d = base()
    s.add(s.response("aB", "resp1", d, "ACCEPTABLE", 2, utility=7))
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, honoured()


def case_33():
    s, d = base()
    s.add(s.response("aB", "resp1", d, "ASK_HUMAN", 2))
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    return s, never_formed()


def case_34():
    s, d = formed_base()
    s.done(d, "oA")
    s.outcome(d, "oB", "done", 1, 15, 16, ident="outoB1")
    s.outcome(d, "oB", "missed", 0, 20, 21, ident="outoB2")
    return s, unknown_performance()


def case_35():
    s, d = formed_base(Scenario(evaluation_tick=8, cutoff=8))
    return s, c.result(None, "pending", "formed", next_deadline=20)


def case_36():
    s, d = base(Scenario(evaluation_tick=8, cutoff=8))
    s.add(s.accept("aA", d, 3))
    return s, c.result(None, "pending", "absent", next_deadline=10)


def case_37():
    s, d = formed_base()
    s.outcome(d, "oA", "missed", 0, 20, 21)
    return s, breached("oA")


def case_38():
    s, d = base()
    s.add(s.accept("aA", d, 3))
    acc_b = s.accept("aB", d, 4)
    s.add({**acc_b, "expiry": 99})  # changed without a new signature
    s.done(d)
    return s, never_formed()


def case_39():
    s, d1 = base()
    d2 = digest_of(s.add(s.propose("prop2", 2, 2, d1)))
    s.add(s.accept("aA", d2, 3))
    s.add(s.accept("aB", d2, 4))
    s.done(d2)
    return s, honoured()


# New wire-level cases.


def case_40():
    """B's ACCEPT is signed with a key that is not the pinned key for aB."""
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4, key_role="mallory"))
    s.done(d)
    return s, never_formed()


def case_41():
    """One signed byte of B's ACCEPT changes after canonical encoding."""
    s, d = base()
    s.add(s.accept("aA", d, 3))
    raw = wire(s.accept("aB", d, 4, expiry=9))
    s.add(alter_signed_byte(raw, b'"expiry":9', b'"expiry":8'), 4)  # still in scope; only the signature fails
    s.done(d)
    return s, never_formed()


def case_42():
    """One signed byte of an ENTRY wrapper changes after the operator signed it."""
    s, d = formed_base()
    s.done(d)
    s.alter_entry = 4
    return s, unknown_formation()


def case_43():
    """B's ACCEPT arrives only as a noncanonical encoding of the same signed envelope."""
    s, d = base()
    s.add(s.accept("aA", d, 3))
    acc_b = s.accept("aB", d, 4)
    s.add(json.dumps(acc_b, sort_keys=True, separators=(", ", ": ")).encode(), 4)
    s.done(d)
    return s, never_formed()


def case_44():
    """The operator chain has a gap: one ENTRY is missing between signed links."""
    s, d = base()
    s.add(s.accept("aA", d, 3))
    s.add(s.revoke("aA", "revA", "ACCEPT", "accA", 3))  # the omitted entry
    s.add(s.accept("aB", d, 4))
    s.done(d)
    s.drop_entry = 5
    return s, unknown_formation()


def case_45():
    """A wrapped event exceeds the 4096-byte event limit; the ENTRY breaks the grammar."""
    s, d = base()
    s.add(s.accept("aA", d, 3))
    raw = wire(s.accept("aB", d, 4))
    s.add(b" " * (4097 - len(raw)) + raw, 4)
    s.done(d)
    return s, unknown_formation()


def case_46():
    """Authenticated receipt IDs cannot be reused across proposal digests."""
    s, d1 = base()
    p2 = s.add(s.propose("prop2", 2, 2, d1))
    s.add(s.accept("aA", d1, 3))
    s.add(s.accept("aB", d1, 4))
    s.outcome(d1, "oA", "done", 1, 15, 16, ident="collision")
    s.outcome(digest_of(p2), "oA", "done", 1, 16, 17, ident="collision")
    return s, unknown_formation()


CASES = [
    ("01_honoured_direct", case_01),
    ("02_missing_signature", case_02),
    ("03_missing_mandate", case_03),
    ("04_scope_mismatch", case_04),
    ("05_expiry_at_boundary", case_05),
    ("06_acceptance_expiry", case_06),
    ("07_first_mandate_expires", case_07),
    ("08_stale_acceptance", case_08),
    ("09_conflicting_acceptance_revisions", case_09),
    ("10_equivocation_same_revision", case_10),
    ("11_conditional_without_proof", case_11),
    ("12_condition_true_then_fresh_accepts", case_12),
    ("13_late_condition_no_auto_consent", case_13),
    ("14_revoke_acceptance_before_formation", case_14),
    ("15_revoke_mandate_before_formation", case_15),
    ("16_revoke_after_formation", case_16),
    ("17_exact_replay_idempotent", case_17),
    ("18_cross_session_replay", case_18),
    ("19_authenticated_message_id_collision", case_19),
    ("20_partial_closed_record", case_20),
    ("21_partial_open_record", case_21),
    ("22_missing_performance_receipt", case_22),
    ("23_closed_observer_no_delivery", case_23),
    ("24_signed_failure", case_24),
    ("25_late_delivery", case_25),
    ("26_missing_formation_log", case_26),
    ("27_unavailable_verifier", case_27),
    ("28_referee_absent", case_28),
    ("29_referee_certificate", case_29),
    ("30_referee_late_certificate", case_30),
    ("31_acceptable_is_not_consent", case_31),
    ("32_preference_payload_rejected", case_32),
    ("33_ask_human_pauses", case_33),
    ("34_conflicting_observer_evidence", case_34),
    ("35_performance_pending", case_35),
    ("36_formation_pending", case_36),
    ("37_breach_dominates_other_unknown", case_37),
    ("38_tampered_signed_field", case_38),
    ("39_fresh_revision_forms", case_39),
    ("40_wrong_public_key", case_40),
    ("41_altered_signed_byte", case_41),
    ("42_altered_entry_byte", case_42),
    ("43_noncanonical_encoding", case_43),
    ("44_checkpoint_gap", case_44),
    ("45_event_byte_limit_breach", case_45),
    ("46_cross_revision_receipt_id_collision", case_46),
]

# Verdict and evidence status for 01 to 39, copied from the spec/evidence.md
# research table. A test checks each generated expectation against this table.
SPEC_TABLE = {
    "01": ("honoured", "complete"), "02": ("never formed", "complete"), "03": ("never formed", "complete"),
    "04": ("never formed", "complete"), "05": ("never formed", "complete"), "06": ("never formed", "complete"),
    "07": ("never formed", "complete"), "08": ("never formed", "complete"), "09": ("never formed", "complete"),
    "10": ("never formed", "complete"), "11": ("never formed", "complete"), "12": ("honoured", "complete"),
    "13": ("never formed", "complete"), "14": ("never formed", "complete"), "15": ("never formed", "complete"),
    "16": ("honoured", "complete"), "17": ("honoured", "complete"), "18": ("never formed", "complete"),
    "19": (None, "unknown"), "20": ("breached", "complete"), "21": (None, "unknown"),
    "22": (None, "unknown"), "23": ("breached", "complete"), "24": ("breached", "complete"),
    "25": ("breached", "complete"), "26": (None, "unknown"), "27": (None, "unknown"),
    "28": ("never formed", "complete"), "29": ("honoured", "complete"), "30": ("never formed", "complete"),
    "31": ("never formed", "complete"), "32": ("honoured", "complete"), "33": ("never formed", "complete"),
    "34": (None, "unknown"), "35": (None, "pending"), "36": (None, "pending"),
    "37": ("breached", "complete"), "38": ("never formed", "complete"), "39": ("honoured", "complete"),
}


def build_cases() -> list[dict]:
    out = []
    for case_id, fn in CASES:
        scenario, expected = fn()
        out.append({"case": case_id, "expected": expected, "transcript": scenario.transcript()})
    return out


def render_fixture() -> bytes:
    return b"".join(m.canonical(case) + b"\n" for case in build_cases())


def load_fixture() -> list[dict]:
    return [json.loads(line) for line in FIXTURE.read_bytes().splitlines() if line.strip()]


FIXTURE_CASES = load_fixture() if FIXTURE.exists() else []

# ---------------------------------------------------------------------------
# Tests: one per case, against the expected value stored in the fixture.


@pytest.mark.parametrize("case", FIXTURE_CASES, ids=[x["case"] for x in FIXTURE_CASES])
def test_case(case: dict) -> None:
    expected = case["expected"]
    assert c.check(case["transcript"]) == expected


def test_fixture_has_every_case() -> None:
    assert [x["case"] for x in FIXTURE_CASES] == [cid for cid, _ in CASES]
    assert len(FIXTURE_CASES) == 46


def test_fixture_is_reproducible() -> None:
    assert FIXTURE.read_bytes() == render_fixture()


def test_research_expectations_match_spec_table() -> None:
    for case in FIXTURE_CASES:
        prefix = case["case"][:2]
        if prefix in SPEC_TABLE:
            exp = case["expected"]
            assert (exp["verdict"], exp["evidence_status"]) == SPEC_TABLE[prefix], case["case"]
    assert len(SPEC_TABLE) == 39


def test_spec_table_ids_match_evidence_md() -> None:
    text = (ROOT / "spec" / "evidence.md").read_text(encoding="utf-8")
    spec_ids = [line.split("|")[1].strip() for line in text.splitlines() if line.startswith("| ") and line[2:4].isdigit()]
    assert spec_ids == [cid for cid, _ in CASES[:39]]
    for line in text.splitlines():
        if line.startswith("| ") and line[2:4].isdigit():
            cells = [x.strip() for x in line.strip("|").split("|")]
            verdict = None if cells[2] == "null" else cells[2]
            assert (verdict, cells[3]) == SPEC_TABLE[cells[0][:2]], cells[0]


def test_unresolved_results_carry_no_terminal_verdict() -> None:
    for case in FIXTURE_CASES:
        for res in (case["expected"], c.check(case["transcript"])):
            if res["evidence_status"] in ("unknown", "pending"):
                assert res["verdict"] is None, case["case"]
            else:
                assert res["verdict"] in c.TERMINAL_VERDICTS, case["case"]
            if res["verdict"] != "breached":
                assert res["failed_obligations"] == [], case["case"]
            assert (res["next_deadline"] is not None) == (res["evidence_status"] == "pending"), case["case"]


def test_result_fields_match_protocol() -> None:
    proto = json.loads((ROOT / "spec" / "protocol.json").read_text(encoding="utf-8"))
    fields = proto["checker"]["required_output_fields"]
    outputs = proto["checker"]["outputs"]
    for case in FIXTURE_CASES:
        res = c.check(case["transcript"])
        assert list(res) == fields
        assert res["verdict"] in outputs["verdict"]
        assert res["evidence_status"] in outputs["evidence_status"]
        assert res["formation"] in outputs["formation"]


def test_check_is_pure_and_total() -> None:
    case = FIXTURE_CASES[0]
    before = json.dumps(case["transcript"], sort_keys=True)
    assert c.check(case["transcript"]) == c.check(case["transcript"])
    assert json.dumps(case["transcript"], sort_keys=True) == before
    for bad in (None, [], "x", {}, {"trust": {}}):
        assert c.check(bad) == c.result(None, "unknown", "unknown")


# ---------------------------------------------------------------------------
# Wire grammar


def test_grammar_matches_protocol_json() -> None:
    proto = json.loads((ROOT / "spec" / "protocol.json").read_text(encoding="utf-8"))
    wire_spec = proto["wire"]
    assert wire_spec["kind_byte_limits"] == m.KIND_BYTE_LIMITS
    assert wire_spec["max_signed_message_bytes"] == m.MAX_SIGNED_MESSAGE_BYTES
    assert set(wire_spec["common_fields"]) == set(m.COMMON_FIELDS)
    assert set(wire_spec["messages"]) == set(m.MESSAGES)
    for kind, spec in wire_spec["messages"].items():
        assert spec["required"] == m.MESSAGES[kind]["required"], kind
        assert spec["optional"] == m.MESSAGES[kind]["optional"], kind
    assert wire_spec["types"]["event_bytes"]["max_decoded_bytes"] == m.MAX_EVENT_DECODED_BYTES
    assert wire_spec["types"]["event_bytes"]["max_bytes"] == m.MAX_EVENT_BYTES_CHARS
    assert wire_spec["types"]["uint"]["max"] == m.UINT_MAX
    assert proto["proposal"]["digest_fields"] == [
        "version", "session", "id", "signer", "kind", "tick",
        *m.MESSAGES["PROPOSE"]["required"],
    ]


def _accept_msg() -> dict:
    return Scenario().accept("aA", "0" * 64, 3)


def _reason(data: bytes) -> str:
    with pytest.raises(m.Rejected) as err:
        m.parse_message(data)
    return err.value.reason


def test_valid_message_round_trips() -> None:
    msg = _accept_msg()
    assert m.parse_message(wire(msg)) == msg
    assert m.verify_signature(msg, m.decode_public_key(PUBLIC["aA"]))


def test_wrong_public_key_fails() -> None:
    msg = _accept_msg()
    assert not m.verify_signature(msg, m.decode_public_key(PUBLIC["aB"]))


def test_altered_signed_byte_fails_signature() -> None:
    raw = alter_signed_byte(wire(_accept_msg()), b'"tick":3', b'"tick":4')
    msg = m.parse_message(raw)  # still grammatical and canonical
    assert not m.verify_signature(msg, m.decode_public_key(PUBLIC["aA"]))


def test_noncanonical_encoding_rejected() -> None:
    msg = _accept_msg()
    assert _reason(json.dumps(msg, sort_keys=True, indent=1).encode()) == "noncanonical"
    assert _reason(json.dumps(msg).encode()) == "noncanonical"  # key order


def test_strict_json_rules() -> None:
    raw = wire(_accept_msg())
    assert _reason(b"\xef\xbb\xbf" + raw) == "bom"
    assert _reason(raw[:-1] + b',"tick":3}') == "duplicate_key"
    assert _reason(raw.replace(b'"tick":3', b'"tick":3.0')) == "float"
    assert _reason(raw.replace(b'"tick":3', b'"tick":3e0')) == "float"
    assert _reason(raw.replace(b'"tick":3', b'"tick":true')) == "type:uint"
    assert _reason(raw.replace(b'"version":1', b'"version":true')) == "type:{'const': 1}"
    assert _reason(b"\xff" + raw) == "utf8"
    assert _reason(raw[:-1] + b',"note":"x"}') == "unknown_field:note"


def test_negative_zero_rejected() -> None:
    raw = wire(_accept_msg()).replace(b'"tick":3', b'"tick":-0')
    with pytest.raises(m.Rejected):
        m.parse_message(raw)


def test_missing_signature_rejected() -> None:
    assert _reason(wire(m.unsigned(_accept_msg()))) == "missing_field:signature"


def test_response_byte_limit() -> None:
    # A CONDITIONAL with eight 32-byte condition IDs is grammatical but over 512 bytes.
    long_ids = sorted(f"c{i}" + "x" * 30 for i in range(8))
    msg = Scenario().response("aB", "r1", "0" * 64, "CONDITIONAL", 2, condition_ids=long_ids)
    raw = wire(msg)
    assert len(raw) > 512
    assert _reason(raw) == "byte_limit"


def test_wire_byte_limit_before_parse() -> None:
    assert _reason(b"{" + b" " * 9000 + b"}") == "byte_limit"


def test_event_bytes_limit() -> None:
    with pytest.raises(m.Rejected):
        m._check_type(m.b64url_encode(b"x" * 4097), "event_bytes")
    m._check_type(m.b64url_encode(b"x" * 4096), "event_bytes")


def test_base64url_canonical() -> None:
    assert m.b64url_decode(m.b64url_encode(b"ab")) == b"ab"
    with pytest.raises(m.Rejected):
        m.b64url_decode("YWI=")  # padding
    with pytest.raises(m.Rejected):
        m.b64url_decode("YWJ")  # nonzero trailing bits


def test_canonical_json_rfc8785_strings() -> None:
    value = {"b": "€\n\u0001\"", "a": [True, None, 0], "é": 1}
    assert m.canonical(value) == '{"a":[true,null,0],"b":"€\\n\\u0001\\"","é":1}'.encode()


def test_cli_prints_one_result_per_transcript(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "accord.checker", str(FIXTURE)], capture_output=True, env=env, check=False
    )
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.decode().splitlines()
    assert [json.loads(x) for x in lines] == [x["expected"] for x in FIXTURE_CASES]


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_bytes(render_fixture())
        print(f"wrote {len(CASES)} cases to {FIXTURE}")
    else:
        print("usage: python3 tests/test_checker.py --write", file=sys.stderr)
        raise SystemExit(2)


@pytest.mark.parametrize("order", ["form_then_abort", "abort_then_form"])
@pytest.mark.parametrize("abort_tick", [5, 6])
def test_release_referee_decision_conflict(order, abort_tick):
    s, d = referee_base()
    form = s.form(d, 5 if order == "form_then_abort" else abort_tick)
    abort = sign(dict(id="abort1", signer="ref", kind="ABORT", tick=abort_tick, digest=d))
    for msg in ((form, abort) if order == "form_then_abort" else (abort, form)):
        s.add(msg)
    s.done(d)
    assert c.check(s.transcript()) == unknown_formation()


def test_release_formed_obligations_survive_later_events():
    s, d = referee_base()
    form = s.form(d, 5)
    s.add(form)
    s.add(s.propose("prop2", 6, 2, d))
    s.add(s.revoke("aA", "revA", "ACCEPT", "accA", 6))
    s.add(form, 7)  # Exact decision replay supplies no new decision.
    s.done(d)
    assert c.check(s.transcript()) == honoured()


def test_release_veto_then_both_accepts():
    s, d = base()
    s.add(s.response("aB", "veto1", d, "VETO", 2))
    s.add(s.accept("aA", d, 3))
    s.add(s.accept("aB", d, 4))
    s.done(d)
    assert c.check(s.transcript()) == never_formed()


def test_release_veto_allows_new_revision():
    s, d = base()
    s.add(s.response("aB", "veto1", d, "VETO", 2))
    new = digest_of(s.add(s.propose("prop2", 2, 2, d)))
    s.add(s.accept("aA", new, 3))
    s.add(s.accept("aB", new, 4))
    s.done(new)
    assert c.check(s.transcript()) == honoured()


def test_release_veto_does_not_revoke_prior_consent():
    s, d = referee_base()
    s.add(s.response("aB", "veto1", d, "VETO", 4))
    s.add(s.form(d, 5))
    s.done(d)
    assert c.check(s.transcript()) == honoured()


@pytest.mark.parametrize("formed", [False, True])
@pytest.mark.parametrize("evaluation_tick", [8, 30])
def test_release_receipt_collision_before_verdict(formed, evaluation_tick):
    s, d = (formed_base if formed else base)(Scenario(evaluation_tick, evaluation_tick))
    s.outcome(d, "oA", "done", 1, 15, 16, ident="collision")
    s.outcome(d, "oA", "missed", 0, 20, 21, ident="collision")
    assert c.check(s.transcript()) == (unknown_performance() if formed else unknown_formation())


@pytest.mark.parametrize("evaluation_tick", [19, 20, 21])
def test_release_deadline_at_evaluation(evaluation_tick):
    s, d = formed_base(Scenario(evaluation_tick, evaluation_tick))
    expected = (c.result(None, "pending", "formed", next_deadline=20)
                if evaluation_tick < 20 else unknown_performance())
    assert c.check(s.transcript()) == expected


def test_release_completion_at_deadline_is_timely():
    s, d = formed_base(Scenario(20, 20))
    for oid in ("oA", "oB"):
        s.outcome(d, oid, "done", 1, 20, 20)
    assert c.check(s.transcript()) == honoured()
