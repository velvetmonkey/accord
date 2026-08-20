# accord

A protocol for discovering and settling **commitments** between sovereign principals,
human or machine, without either side having to disclose the mind that produced them.

> **Status: placeholder.** There is no code here yet. This repository exists so the
> idea is not forgotten and the name is reserved. Nothing in this programme starts
> until [seal](https://github.com/velvetmonkey/seal) is finished.

## The design principle

> Do not infer what you can coordinate without knowing.

Most coordination does not need a model of what anyone wants. It needs only:
I reject this. I accept this. I accept this if X changes. I prefer A to B here.
I authorise this exact outcome.

So the acceptance function of a principal is **opaque** to this protocol. A principal
may run an elaborate private preference model, or a hand-written list of rules, or ask
a human every time. The wire cannot tell, and does not need to.

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

Each carries confidence, conditions and expiry. None of them exposes why.

## The open question this repository must answer first

Can a useful negotiation run entirely on these responses, with no preference model
anywhere in the loop? If yes, the wider programme no longer depends on preference
inference being solved. If no, the exact step that requires inference must be named.

## The invariants this programme inherits

These hold across every repository in the set. They are not decoration.

- **Legibility is not consent.** That something can be inferred does not make every use of it legitimate.
- **Inference is not authority.** An agent may believe I prefer X and still have no authority to do X.
- **Coordination does not require surrender.**
- A valid mandate is **necessary** for action. It is **not sufficient** for legitimacy.
- Use CRDTs to converge the record, not to converge the people.

## The type chain

No stage may impersonate the next. Each transition owes a two-sided test: red on the
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
| [accord](https://github.com/velvetmonkey/accord) | The protocol. Opaque acceptance, minimal disclosure. |
| [accord-settlement](https://github.com/velvetmonkey/accord-settlement) | Stateful commitments and composition above the effect boundary. |
| [accord-contest](https://github.com/velvetmonkey/accord-contest) | Standing, challenge, remedy, precedent. |
| [reveal-lab](https://github.com/velvetmonkey/reveal-lab) | The hostile benchmark. Lets the central claim die cheaply. |
| [preference-kernel](https://github.com/velvetmonkey/preference-kernel) | Optional private cognition, behind the sovereign boundary. |
| [agency-boundary](https://github.com/velvetmonkey/agency-boundary) | Roles, delegation and standing for persistent agents. |
| [seal](https://github.com/velvetmonkey/seal) | The finished authority boundary. One exact effect, one receipt. |

Licence: not yet chosen.
