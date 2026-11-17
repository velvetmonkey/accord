# accord

A protocol for binding deals between principals, human or machine. Each side sends
answers to proposals. No side sends its preferences.

> **Status: placeholder, research programme, starts after Project Tenter.** There is no
> code here yet. This file records the question, the end state and the known limit.

## The question

Can two agents reach a binding deal when they send only `VETO`, `ACCEPTABLE`, `COUNTER`
and the rest of the vocabulary below, and never send their preferences? If they can,
what does that privacy cost?

## The design principle

> Do not infer what you can coordinate without knowing.

Most coordination does not need a model of what anyone wants. It needs only:
I reject this. I accept this. I accept this if X changes. I prefer A to B here.
I authorise this exact outcome.

So the acceptance function of a principal is **opaque** to this protocol. A principal
can run a private preference model, a hand-written list of rules, or ask a human each
time. The wire cannot see the difference, and it does not need to.

## What crosses the wire

    Proposal
    Constraint
    Counteroffer
    Acceptance
    Mandate
    Commitment
    Revocation
    DecisionReceipt

## What never crosses the wire

    Personality
    Memory
    UtilityFunction
    PreferenceGraph

## The disclosure vocabulary

A principal answers a proposal with one of:

    VETO  ACCEPTABLE  PREFERRED  COUNTER  CONDITIONAL  DEFER  ASK_HUMAN

Each answer carries confidence, conditions and expiry. No answer tells why.

## The end state

1. **A specification** of the messages, the vocabulary and the state machine of a deal.
2. **A reference implementation** of the specification.
3. **A negotiation arena.** It runs the same negotiations two times: one time with the
   protocol, one time with full disclosure of preferences. It measures the welfare that
   the privacy costs.
4. **A transcript checker.** It reads a deal transcript and gives one verdict:
   `honoured`, `breached` or `never formed`.

## The fair-exchange limit

Two signatures stop one side from changing a deal after both sides sign. They do not
make formation fair. Fair exchange without a trusted third party is a known impossible
result (Pagnia and Gärtner, 1999). One side always sends its last message first, and the
other side can stop at that point.

So this protocol does not claim fair formation without help. It supports an optional
referee. Without the referee, the transcript checker can report `never formed`, and the
research question becomes how often that happens and what it costs.

## The invariants this programme inherits

These hold across every repository in the set. They are not decoration.

- **Legibility is not consent.** That something can be inferred does not make every use of it legitimate.
- **Inference is not authority.** An agent may believe I prefer X and still have no authority to do X.
- **Coordination does not require surrender.**
- A valid mandate is **necessary** for action. It is **not sufficient** for legitimacy.
- Use CRDTs to converge the record, not to converge the people.

## The type chain

No stage may impersonate the next. Each transition needs a two-sided test: red on the
illegal construction, green on the legal one.

    Fact
      -> PreferenceEvidence
      -> PreferenceHypothesis
      -> Endorsement
      -> Mandate
      -> Commitment
      -> Effect
      -> OutcomeReceipt

## Siblings

| Repository | Role |
|---|---|
| [accord-settlement](https://github.com/velvetmonkey/accord-settlement) | The session guard. Stops allowed actions from combining into a leak. |
| [accord](https://github.com/velvetmonkey/accord) | The protocol. Binding deals without disclosure of preferences. |
| [reveal-lab](https://github.com/velvetmonkey/reveal-lab) | The hostile benchmark for LLM mediators. |
| [seal](https://github.com/velvetmonkey/seal) | The finished authority boundary. One exact effect, one receipt. |

A planned essay, "Who can object?", covers agency law for agents and standing for
parties that a deal leaves out.

Licence: [Apache-2.0](LICENSE).
