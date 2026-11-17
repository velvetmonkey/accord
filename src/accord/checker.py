"""Accord version 1 reference transcript checker.

check(transcript) is a pure function. It does no network, clock or file
access. It reads a transcript object and returns the result object that
spec/evidence.md and spec/protocol.json (checker section) define.

Transcript object (all byte strings are canonical unpadded base64url):

    {
      "trust": {
        "session": <session id>,
        "session_digest": <event digest of the complete signed SESSION>,
        "log_operator": <id>,
        "keys": {<signer id>: <43-char base64url Ed25519 public key>},
        "catalog": <public catalog object>,
        "coverage_observers": [<observer ids trusted for exclusive coverage>]
      },
      "evaluation_tick": <uint>,
      "log": [<ENTRY wire bytes>, ...],
      "checkpoint": <CHECKPOINT wire bytes> or null,
      "receipts": [<OUTCOME or COVERAGE wire bytes>, ...]
    }

Catalog object:

    {
      "terms": [<terms id>, ...],
      "conditions": {<id>: {"observer": <id>, "predicate": <id>}},
      "obligations": {<id>: {"debtor", "action", "quantity", "deadline",
                             "observer", "predicate"}}
    }

The command `python3 -m accord.checker FILE` reads JSON Lines. Each line is a
transcript object, or an object with a "transcript" member. It prints one
canonical JSON result per line.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from . import messages as m

HONOURED = "honoured"
BREACHED = "breached"
NEVER_FORMED = "never formed"
TERMINAL_VERDICTS = (HONOURED, BREACHED, NEVER_FORMED)


def result(
    verdict: str | None,
    evidence_status: str,
    formation: str,
    failed_obligations: list[dict[str, str]] | None = None,
    next_deadline: int | None = None,
) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "evidence_status": evidence_status,
        "formation": formation,
        "failed_obligations": list(failed_obligations or []),
        "next_deadline": next_deadline,
    }


def _unknown() -> dict[str, Any]:
    return result(None, "unknown", "unknown")


class _Unknown(Exception):
    """Formation record missing, incomplete, contradictory or unverifiable."""


# ---------------------------------------------------------------------------
# Trust configuration


@dataclass
class _Trust:
    session: str
    session_digest: str
    log_operator: str
    keys: dict[str, bytes]
    catalog: dict[str, Any]
    catalog_digest: str
    coverage_observers: frozenset[str]


def _read_trust(raw: Any) -> _Trust:
    if type(raw) is not dict:
        raise _Unknown("trust")
    try:
        session = raw["session"]
        sdigest = raw["session_digest"]
        log_operator = raw["log_operator"]
        keys_in = raw["keys"]
        catalog = raw["catalog"]
        coverage = raw.get("coverage_observers", [])
    except KeyError:
        raise _Unknown("trust") from None
    if not (m._is_id(session) and m._is_id(log_operator) and type(sdigest) is str):
        raise _Unknown("trust")
    if type(keys_in) is not dict or type(coverage) is not list or not all(m._is_id(x) for x in coverage):
        raise _Unknown("trust")
    keys: dict[str, bytes] = {}
    try:
        for signer, text in keys_in.items():
            if not m._is_id(signer):
                raise _Unknown("trust")
            keys[signer] = m.decode_public_key(text)
        if not _catalog_ok(catalog):
            raise _Unknown("catalog")
        catalog_digest = m.sha256_hex(m.canonical(catalog))
    except m.Rejected:
        raise _Unknown("trust") from None
    return _Trust(session, sdigest, log_operator, keys, catalog, catalog_digest, frozenset(coverage))


def _catalog_ok(catalog: Any) -> bool:
    if type(catalog) is not dict or set(catalog) != {"terms", "conditions", "obligations"}:
        return False
    if type(catalog["terms"]) is not list or not all(m._is_id(x) for x in catalog["terms"]):
        return False
    for name, item in (("conditions", "condition"), ("obligations", "obligation")):
        table = catalog[name]
        if type(table) is not dict:
            return False
        for ident, entry in table.items():
            if type(entry) is not dict:
                return False
            try:
                m._check_type({"id": ident, **entry}, item)
            except m.Rejected:
                return False
    return True


# ---------------------------------------------------------------------------
# Formation state


@dataclass
class _Session:
    msg: dict[str, Any]

    @property
    def principals(self) -> list[str]:
        return self.msg["principals"]

    @property
    def agents(self) -> list[str]:
        return self.msg["agents"]


@dataclass
class _Event:
    msg: dict[str, Any]
    pos: int  # ENTRY sequence
    tick: int


@dataclass
class _Formation:
    trust: _Trust
    session: _Session
    sdigest: str
    current: _Event | None = None
    current_digest: str | None = None
    proposals: dict[str, _Event] = field(default_factory=dict)  # digest -> proposal
    blocked: bool = False
    vetoes: dict[str, int] = field(default_factory=dict)  # digest -> first VETO position
    closed: bool = False  # referee ABORT
    formed: tuple[str, _Event, int] | None = None  # digest, proposal, formation tick
    mandates: dict[str, _Event] = field(default_factory=dict)  # mandate message id -> event
    revocation_ids: dict[str, str] = field(default_factory=dict)  # revocation id -> principal
    revoked_rids: set[str] = field(default_factory=set)
    accept_signers: dict[str, str] = field(default_factory=dict)  # accept id -> signer
    revoked_accepts: set[str] = field(default_factory=set)
    pending: dict[str, _Event] = field(default_factory=dict)  # agent -> accept
    proofs: dict[tuple[str, str], int] = field(default_factory=dict)  # (digest, cond) -> pos
    false_proofs: set[tuple[str, str]] = field(default_factory=set)
    pause_pos: int | None = None
    responses: int = 0
    referee_decisions: set[bytes] = field(default_factory=set)

    # -- helpers ---------------------------------------------------------

    def principal_of(self, agent: str) -> str | None:
        agents = self.session.agents
        return self.session.principals[agents.index(agent)] if agent in agents else None

    def agent_of(self, principal: str) -> str | None:
        principals = self.session.principals
        return self.session.agents[principals.index(principal)] if principal in principals else None

    def proposal_ok(self, msg: dict[str, Any]) -> bool:
        s = self.session.msg
        cat = self.trust.catalog
        if msg["signer"] != s["proposer"]:
            return False
        if msg["terms"] not in cat["terms"]:
            return False
        if msg["expiry"] > s["expiry"] or not msg["tick"] < msg["expiry"]:
            return False
        if msg["mode"] == "direct":
            if msg["referee"] is not None:
                return False
        elif s["referee"] is None or msg["referee"] != s["referee"]:
            return False
        for cond in msg["conditions"]:
            entry = cat["conditions"].get(cond["id"])
            if entry is None or {k: v for k, v in cond.items() if k != "id"} != entry:
                return False
        for obl in msg["obligations"]:
            entry = cat["obligations"].get(obl["id"])
            if entry is None or {k: v for k, v in obl.items() if k != "id"} != entry:
                return False
            if obl["debtor"] not in self.session.principals:
                return False
            if not obl["deadline"] > msg["expiry"]:
                return False
        return True

    def mandate_ok(self, ev: _Event, agent: str, proposal: dict[str, Any], t: int) -> bool:
        md = ev.msg
        principal = self.principal_of(agent)
        if md["principal"] != principal or md["agent"] != agent or md["signer"] != principal:
            return False
        if md["setup_digest"] != self.sdigest or md["action"] != "accept":
            return False
        if proposal["terms"] not in md["terms"]:
            return False
        own = [o for o in proposal["obligations"] if o["debtor"] == principal]
        if not {o["action"] for o in own} <= set(md["actions"]):
            return False
        if sum(o["quantity"] for o in own) > md["max_quantity"]:
            return False
        if not md["start"] <= t < md["expiry"]:
            return False
        if md["revocation_id"] in self.revoked_rids:
            return False
        if self.pause_pos is not None and ev.pos < self.pause_pos:
            return False
        return True

    def accept_ok(self, ev: _Event, t: int) -> bool:
        """Every consent rule for one ACCEPT, checked at log tick t."""
        acc = ev.msg
        if self.blocked or self.closed or self.current is None:
            return False
        if acc["digest"] != self.current_digest or acc["id"] in self.revoked_accepts:
            return False
        if ev.pos > self.vetoes.get(acc["digest"], ev.pos):
            return False  # A VETO rejects new consent, but does not revoke earlier ACCEPT.
        if self.pause_pos is not None and (ev.pos < self.pause_pos or not self.resumed()):
            return False
        proposal = self.current.msg
        s = self.session.msg
        if acc["expiry"] > proposal["expiry"] or not acc["tick"] <= t < acc["expiry"]:
            return False
        if not proposal["tick"] <= t < proposal["expiry"]:
            return False
        if not s["start"] <= t < s["expiry"]:
            return False
        md = self.mandates.get(acc["mandate"])
        if md is None or not self.mandate_ok(md, acc["signer"], proposal, t):
            return False
        for cond in proposal["conditions"]:
            key = (self.current_digest, cond["id"])
            if key in self.false_proofs or key not in self.proofs or self.proofs[key] >= ev.pos:
                return False
        return True

    def resumed(self) -> bool:
        """After ASK_HUMAN, each principal must issue a fresh mandate."""
        assert self.pause_pos is not None
        fresh = {ev.msg["principal"] for ev in self.mandates.values() if ev.pos > self.pause_pos}
        return set(self.session.principals) <= fresh

    # -- event handlers --------------------------------------------------

    def apply(self, ev: _Event) -> None:
        if self.formed is not None:
            if ev.msg["kind"] in ("FORM", "ABORT"):
                self._record_referee_decision(ev)
            return  # Keep the formed deal while collecting signed conflicts.
        handler = getattr(self, "on_" + ev.msg["kind"].lower(), None)
        if handler is not None:
            handler(ev)

    def on_propose(self, ev: _Event) -> None:
        msg = ev.msg
        if not self.proposal_ok(msg):
            return
        digest = m.proposal_digest(msg)
        cur = self.current
        if cur is None:
            if msg["revision"] != 1 or msg["previous"] is not None:
                return
        else:
            if msg["proposal_id"] != cur.msg["proposal_id"]:
                return
            if msg["revision"] == cur.msg["revision"] and msg["previous"] == cur.msg["previous"]:
                if digest != self.current_digest:
                    self.blocked = True  # Equivocation at one revision blocks the session.
                return
            if msg["revision"] != cur.msg["revision"] + 1 or msg["previous"] != self.current_digest:
                return
        self.current = ev
        self.current_digest = digest
        self.proposals[digest] = ev
        self.pending.clear()  # Consent to an old digest cannot carry over.

    def on_mandate(self, ev: _Event) -> None:
        md = ev.msg
        if md["signer"] != md["principal"] or md["principal"] not in self.session.principals:
            return
        if md["agent"] != self.agent_of(md["principal"]) or md["setup_digest"] != self.sdigest:
            return
        if not md["start"] < md["expiry"]:
            return
        if md["revocation_id"] in self.revocation_ids:
            return
        self.revocation_ids[md["revocation_id"]] = md["principal"]
        self.mandates[md["id"]] = ev

    def on_accept(self, ev: _Event) -> None:
        acc = ev.msg
        agent = acc["signer"]
        if agent not in self.session.agents:
            return
        self.accept_signers[acc["id"]] = agent
        if not self.accept_ok(ev, ev.tick):
            return
        self.pending[agent] = ev
        if self.current is not None and self.current.msg["mode"] == "direct":
            self.try_form([self.pending.get(a) for a in self.session.agents], ev.tick)

    def try_form(self, accepts: list[_Event | None], t: int) -> bool:
        if any(a is None for a in accepts):
            return False
        if not all(self.accept_ok(a, t) for a in accepts if a is not None):
            return False
        assert self.current is not None and self.current_digest is not None
        self.formed = (self.current_digest, self.current, t)
        return True

    def on_revoke(self, ev: _Event) -> None:
        msg = ev.msg
        if msg["target_kind"] == "MANDATE":
            if self.revocation_ids.get(msg["target"]) == msg["signer"]:
                self.revoked_rids.add(msg["target"])
        else:
            if self.accept_signers.get(msg["target"]) == msg["signer"]:
                self.revoked_accepts.add(msg["target"])
                pend = self.pending.get(msg["signer"])
                if pend is not None and pend.msg["id"] == msg["target"]:
                    del self.pending[msg["signer"]]

    def on_condition(self, ev: _Event) -> None:
        msg = ev.msg
        if self.current is None or msg["digest"] != self.current_digest:
            return
        conds = {c["id"]: c for c in self.current.msg["conditions"]}
        cond = conds.get(msg["condition"])
        if cond is None or msg["signer"] != cond["observer"]:
            return
        key = (msg["digest"], msg["condition"])
        if msg["value"]:
            self.proofs.setdefault(key, ev.pos)
        else:
            self.false_proofs.add(key)
        if key in self.proofs and key in self.false_proofs:
            self.blocked = True  # Conflicting certificates need a new session.

    def on_response(self, ev: _Event) -> None:
        msg = ev.msg
        if msg["signer"] not in self.session.agents:
            return
        target = self.proposals.get(msg["digest"])
        if target is None or msg["expiry"] != target.msg["expiry"]:
            return
        if self.responses >= 6:
            return  # protocol.json response_budget
        word = msg["response"]
        optional = {k for k in ("comparison_digest", "counter_digest", "condition_ids", "retry_round") if k in msg}
        need = {
            "PREFERRED": {"comparison_digest"},
            "COUNTER": {"counter_digest"},
            "CONDITIONAL": {"condition_ids"},
            "DEFER": {"retry_round"},
        }.get(word, set())
        if optional != need:
            return
        if word == "PREFERRED" and (
            msg["comparison_digest"] == msg["digest"] or msg["comparison_digest"] not in self.proposals
        ):
            return
        if word == "COUNTER" and msg["counter_digest"] == msg["digest"]:
            return
        if word == "CONDITIONAL":
            ids = {c["id"] for c in target.msg["conditions"]}
            if not msg["condition_ids"] or not set(msg["condition_ids"]) <= ids:
                return
        if word == "DEFER" and not self.responses + 1 < msg["retry_round"] <= 6:
            return
        self.responses += 1
        if word == "VETO":
            self.vetoes.setdefault(msg["digest"], ev.pos)
        if word == "ASK_HUMAN":
            self.pending.clear()
            self.pause_pos = ev.pos

    def _referee_mode(self) -> bool:
        s = self.session.msg
        return (
            s["referee"] is not None
            and self.current is not None
            and self.current.msg["mode"] == "referee"
        )

    def _record_referee_decision(self, ev: _Event) -> bool:
        msg = ev.msg
        if msg["signer"] != self.session.msg["referee"] or not self._referee_mode():
            return False
        self.referee_decisions.add(m.canonical(msg))
        return True

    def on_form(self, ev: _Event) -> None:
        msg = ev.msg
        if not self._record_referee_decision(ev):
            return
        if self.closed or msg["digest"] != self.current_digest:
            return
        accepts = [self.pending.get(a) for a in self.session.agents]
        if any(a is None for a in accepts) or msg["accept_ids"] != [a.msg["id"] for a in accepts if a]:
            return
        self.try_form(accepts, ev.tick)

    def on_abort(self, ev: _Event) -> None:
        msg = ev.msg
        if not self._record_referee_decision(ev):
            return
        if msg["digest"] == self.current_digest and ev.tick < self.session.msg["expiry"]:
            self.closed = True


# ---------------------------------------------------------------------------
# Log verification


def _roles(trust: _Trust, session: dict[str, Any]) -> set[str]:
    roles = {trust.log_operator, *session["principals"], *session["agents"]}
    if session["referee"] is not None:
        roles.add(session["referee"])
    for table in ("conditions", "obligations"):
        roles.update(e["observer"] for e in trust.catalog[table].values())
    return roles


def _key_lookup(trust: _Trust, roles: set[str]):
    def key_for(signer: str) -> bytes | None:
        if signer in trust.keys:
            return trust.keys[signer]
        if signer in roles:
            raise m.Unavailable(f"no pinned key for role {signer}")
        return None

    return key_for


def _parse_signed(raw: bytes, kind: str, trust: _Trust, signer: str) -> dict[str, Any]:
    try:
        msg = m.parse_message(raw)
    except m.Rejected:
        raise _Unknown(kind) from None
    if msg["kind"] != kind or msg["session"] != trust.session or msg["signer"] != signer:
        raise _Unknown(kind)
    key = trust.keys.get(signer)
    if key is None or not m.verify_signature(msg, key):
        raise _Unknown(kind)
    return msg


def _read_log(t: dict[str, Any], trust: _Trust) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    log = t.get("log")
    cp_text = t.get("checkpoint")
    if type(log) is not list or not log or cp_text is None:
        raise _Unknown("formation record missing")
    entries: list[dict[str, Any]] = []
    previous = None
    last_tick = -1
    ids: set[str] = set()
    for index, text in enumerate(log):
        try:
            raw = m.b64url_decode(text)
        except m.Rejected:
            raise _Unknown("entry encoding") from None
        entry = _parse_signed(raw, "ENTRY", trust, trust.log_operator)
        if entry["sequence"] != index + 1 or entry["previous"] != previous:
            raise _Unknown("entry chain gap")
        if entry["tick"] < last_tick or entry["id"] in ids:
            raise _Unknown("entry order")
        ids.add(entry["id"])
        last_tick = entry["tick"]
        previous = m.event_digest(entry)
        entries.append(entry)
    try:
        cp_raw = m.b64url_decode(cp_text)
    except m.Rejected:
        raise _Unknown("checkpoint encoding") from None
    cp = _parse_signed(cp_raw, "CHECKPOINT", trust, trust.log_operator)
    if cp["last_sequence"] != len(entries) or cp["last_entry_digest"] != previous:
        raise _Unknown("checkpoint head")
    if cp["id"] in ids or not cp["tick"] >= cp["cutoff"] >= cp["start"] or last_tick > cp["cutoff"]:
        raise _Unknown("checkpoint coverage")

    first = m.b64url_decode(entries[0]["event_bytes"])
    session = _parse_signed(first, "SESSION", trust, trust.log_operator)
    if m.event_digest(session) != trust.session_digest:
        raise _Unknown("session digest")
    if session["log_operator"] != trust.log_operator or session["catalog_digest"] != trust.catalog_digest:
        raise _Unknown("session trust")
    if session["tick"] != entries[0]["tick"] or not session["start"] <= session["tick"]:
        raise _Unknown("session tick")
    if not session["start"] < session["expiry"] or session["proposer"] != session["agents"][0]:
        raise _Unknown("session setup")
    if len(set(session["principals"]) | set(session["agents"])) != 4:
        raise _Unknown("session roles")
    if cp["start"] != session["start"]:
        raise _Unknown("checkpoint start")
    return entries, cp, session


# ---------------------------------------------------------------------------
# Performance


@dataclass
class _ObligationEvidence:
    snapshots: dict[bytes, dict[str, Any]] = field(default_factory=dict)
    coverage: dict[bytes, dict[str, Any]] = field(default_factory=dict)
    unavailable: bool = False


def _outcome_ok(msg: dict[str, Any], obl: dict[str, Any], formed_tick: int) -> bool:
    if msg["debtor"] != obl["debtor"] or msg["action"] != obl["action"]:
        return False
    if not formed_tick < msg["completed_tick"] <= msg["tick"]:
        return False
    if msg["status"] == "done":
        return msg["quantity"] >= obl["quantity"]
    if msg["quantity"] >= obl["quantity"]:
        return False
    if msg["status"] == "missed":
        return msg["tick"] >= obl["deadline"] and msg["completed_tick"] >= obl["deadline"]
    return True


def _coverage_ok(msg: dict[str, Any], obl: dict[str, Any], formed_tick: int, trust: _Trust) -> bool:
    return (
        obl["observer"] in trust.coverage_observers
        and msg["start"] == formed_tick
        and msg["start"] <= msg["cutoff"] <= msg["tick"]
        and msg["cutoff"] >= obl["deadline"]
    )


def _decide(obl: dict[str, Any], ev: _ObligationEvidence, now: int) -> str:
    """Return performed, failed, unknown or pending for one obligation."""
    if ev.unavailable:
        return "unknown"
    snaps = list(ev.snapshots.values())
    covs = list(ev.coverage.values())
    if len(snaps) > 1 or len({c["quantity"] for c in covs}) > 1:
        return "unknown"  # Distinct snapshots or inconsistent coverage conflict.
    need = obl["quantity"]
    snap = snaps[0] if snaps else None
    cov_qty = covs[0]["quantity"] if covs else None
    if snap is not None:
        if snap["status"] == "done":
            timely = snap["completed_tick"] <= obl["deadline"]
            if cov_qty is not None and (cov_qty >= need) != timely:
                return "unknown"  # Coverage contradicts the snapshot.
            return "performed" if timely else "failed"
        if snap["status"] == "missed":
            if cov_qty is not None and cov_qty >= need:
                return "unknown"
            return "failed"
        # partial: a cumulative observation only.
        if cov_qty is not None:
            if snap["completed_tick"] <= obl["deadline"] and snap["quantity"] > cov_qty:
                return "unknown"
            return "performed" if cov_qty >= need else "failed"
    elif cov_qty is not None:
        return "performed" if cov_qty >= need else "failed"
    return "pending" if now < obl["deadline"] else "unknown"


def _performance(
    t: dict[str, Any],
    trust: _Trust,
    key_for,
    seen: dict[tuple[str, str], bytes],
    digest: str,
    proposal: dict[str, Any],
    formed_tick: int,
    now: int,
) -> dict[str, Any]:
    receipts = t.get("receipts", [])
    if type(receipts) is not list:
        return result(None, "unknown", "formed")
    obligations = {o["id"]: o for o in proposal["obligations"]}
    evidence = {oid: _ObligationEvidence() for oid in obligations}
    for text in receipts:
        try:
            raw = m.b64url_decode(text, m.MAX_SIGNED_MESSAGE_BYTES)
        except m.Rejected:
            continue
        try:
            auth = m.authenticate(raw, key_for)
        except m.Unavailable:
            obj = None
            try:
                obj = m.loads_strict(raw)
            except m.Rejected:
                pass
            oid = obj.get("obligation") if type(obj) is dict else None
            if oid in evidence:
                evidence[oid].unavailable = True
            continue
        if auth is None:
            continue
        key, signed = auth
        if key in seen and seen[key] != signed:
            return result(None, "unknown", "formed")  # authenticated message-ID collision
        seen[key] = signed
        try:
            msg = m.parse_message(raw)
        except m.Rejected:
            continue
        if msg["kind"] not in ("OUTCOME", "COVERAGE") or msg["session"] != trust.session:
            continue
        if msg["tick"] > now or msg["digest"] != digest:
            continue
        obl = obligations.get(msg["obligation"])
        if obl is None or msg["signer"] != obl["observer"]:
            continue
        canon = m.canonical(msg)
        if msg["kind"] == "OUTCOME":
            if _outcome_ok(msg, obl, formed_tick):
                evidence[obl["id"]].snapshots[canon] = msg
        elif _coverage_ok(msg, obl, formed_tick, trust):
            evidence[obl["id"]].coverage[canon] = msg

    states = {oid: _decide(obligations[oid], evidence[oid], now) for oid in sorted(obligations)}
    failed = [{"id": oid, "debtor": obligations[oid]["debtor"]} for oid, s in states.items() if s == "failed"]
    if failed:
        return result(BREACHED, "complete", "formed", failed)
    if any(s == "unknown" for s in states.values()):
        return result(None, "unknown", "formed")
    pending = [obligations[oid]["deadline"] for oid, s in states.items() if s == "pending"]
    if pending:
        return result(None, "pending", "formed", next_deadline=min(pending))
    return result(HONOURED, "complete", "formed")


# ---------------------------------------------------------------------------
# Entry point


def check(transcript: Any) -> dict[str, Any]:
    """Return the Accord result for one transcript. Pure; never raises for bad input."""
    try:
        return _check(transcript)
    except (_Unknown, m.Unavailable):
        return _unknown()


def _check(t: Any) -> dict[str, Any]:
    if type(t) is not dict:
        raise _Unknown("transcript")
    trust = _read_trust(t.get("trust"))
    now = t.get("evaluation_tick")
    if not m._is_uint(now):
        raise _Unknown("evaluation_tick")
    entries, cp, smsg = _read_log(t, trust)
    session = _Session(smsg)
    if cp["cutoff"] < min(now, smsg["expiry"]):
        raise _Unknown("record incomplete through the evaluation cutoff")

    roles = _roles(trust, smsg)
    key_for = _key_lookup(trust, roles)
    state = _Formation(trust, session, trust.session_digest)
    seen: dict[tuple[str, str], bytes] = {}
    replayed: set[bytes] = {m.b64url_decode(entries[0]["event_bytes"])}
    seen[(smsg["session"], smsg["id"])] = m.signed_bytes(smsg)

    for entry in entries[1:]:
        raw = m.b64url_decode(entry["event_bytes"])
        if raw in replayed:
            continue  # Exact byte replay is idempotent.
        replayed.add(raw)
        auth = m.authenticate(raw, key_for)  # Unavailable propagates: unknown.
        if auth is None:
            continue  # Invalid signature or unknown signer: rejected.
        key, signed = auth
        if key in seen and seen[key] != signed:
            raise _Unknown("authenticated message-ID collision")
        seen[key] = signed
        try:
            msg = m.parse_message(raw, max_bytes=m.MAX_SIGNED_MESSAGE_BYTES)
        except m.Rejected:
            continue
        if msg["kind"] in ("ENTRY", "CHECKPOINT", "SESSION"):
            continue
        if msg["session"] != trust.session or msg["tick"] != entry["tick"]:
            continue
        if msg["tick"] > now or msg["tick"] < smsg["start"]:
            continue
        state.apply(_Event(msg, entry["sequence"], entry["tick"]))

    if len(state.referee_decisions) > 1:
        raise _Unknown("conflicting referee decisions")

    # Authenticate all receipts before any terminal decision, even without a deal.
    receipts = t.get("receipts", [])
    if type(receipts) is not list:
        return result(None, "unknown", "formed") if state.formed else _unknown()
    for text in receipts:
        try:
            raw = m.b64url_decode(text, m.MAX_SIGNED_MESSAGE_BYTES)
        except m.Rejected:
            continue
        auth = m.authenticate(raw, key_for)
        if auth is None:
            continue
        key, signed = auth
        if key in seen and seen[key] != signed:
            return result(None, "unknown", "formed") if state.formed else _unknown()
        seen[key] = signed

    if state.formed is None:
        if min(cp["cutoff"], now) >= smsg["expiry"]:
            return result(NEVER_FORMED, "complete", "absent")
        return result(None, "pending", "absent", next_deadline=smsg["expiry"])

    digest, proposal_ev, formed_tick = state.formed
    return _performance(t, trust, key_for, seen, digest, proposal_ev.msg, formed_tick, now)


def main(argv: list[str] | None = None) -> int:
    import json

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python3 -m accord.checker FILE", file=sys.stderr)
        return 2
    with open(args[0], "rb") as handle:
        lines = [line for line in handle.read().splitlines() if line.strip()]
    for line in lines:
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if type(obj) is dict and "transcript" in obj:
            obj = obj["transcript"]
        sys.stdout.write(m.canonical(check(obj)).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
