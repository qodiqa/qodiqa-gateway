------------------------------ MODULE Lifecycle ------------------------------
(* The request lifecycle of /ai/chat as the audit schema v7 defines it (docs/protocol/QODIQA-PROTOCOL.md, "v7 additions"):
   a nonce is consumed first, an INTENT entry is written BEFORE the provider is called, the provider is called at most once per
   nonce, and a DECISION entry closes the request. A crash between INTENT and DECISION leaves an ORPHAN_INTENT (a warning, never a
   second provider call). Append failure is fail-closed: no INTENT, no provider call.
   Model scope: abstract steps only. It models the ordering rules, not the cryptography, the policies or the classifier. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Requests, Nonces, NonceOf        \* NonceOf : Requests -> Nonces (requests may share a nonce: a replay)
CONSTANT EnforceIntent                      \* TRUE = the real rule; FALSE = negative control (provider called without an INTENT)

VARIABLES phase, log, calls, used

vars == <<phase, log, calls, used>>

ModelNonceOf == [r \in Requests |-> IF r = "r3" THEN "n2" ELSE "n1"]

Phases == {"new", "admitted", "intent", "dispatched", "decided", "refused", "orphan"}

Init == /\ phase = [r \in Requests |-> "new"]
        /\ log = <<>>
        /\ calls = [r \in Requests |-> 0]
        /\ used = {}

\* Admission consumes the nonce atomically; a second request with the same nonce is refused (REPLAY_DETECTED) and logged as a BLOCK decision.
Admit(r) == /\ phase[r] = "new" /\ NonceOf[r] \notin used
            /\ used' = used \cup {NonceOf[r]}
            /\ phase' = [phase EXCEPT ![r] = "admitted"]
            /\ UNCHANGED <<log, calls>>

Replay(r) == /\ phase[r] = "new" /\ NonceOf[r] \in used
             /\ phase' = [phase EXCEPT ![r] = "refused"]
             /\ log' = Append(log, [t |-> "DECISION_BLOCK", r |-> r])
             /\ UNCHANGED <<calls, used>>

\* A policy block after admission: a BLOCK decision, never a provider call.
Block(r) == /\ phase[r] = "admitted"
            /\ phase' = [phase EXCEPT ![r] = "refused"]
            /\ log' = Append(log, [t |-> "DECISION_BLOCK", r |-> r])
            /\ UNCHANGED <<calls, used>>

WriteIntent(r) == /\ phase[r] = "admitted"
                  /\ phase' = [phase EXCEPT ![r] = "intent"]
                  /\ log' = Append(log, [t |-> "INTENT", r |-> r])
                  /\ UNCHANGED <<calls, used>>

\* Fail-closed append: the INTENT cannot be written, so the request is refused and the provider is never called.
IntentAppendFails(r) == /\ phase[r] = "admitted"
                        /\ phase' = [phase EXCEPT ![r] = "refused"]
                        /\ log' = Append(log, [t |-> "DECISION_BLOCK", r |-> r])
                        /\ UNCHANGED <<calls, used>>

CallProvider(r) == /\ \/ (phase[r] = "intent")
                      \/ (~EnforceIntent /\ phase[r] = "admitted")      \* negative control only
                   /\ phase' = [phase EXCEPT ![r] = "dispatched"]
                   /\ calls' = [calls EXCEPT ![r] = @ + 1]
                   /\ UNCHANGED <<log, used>>

WriteDecision(r) == /\ phase[r] = "dispatched"
                    /\ phase' = [phase EXCEPT ![r] = "decided"]
                    /\ log' = Append(log, [t |-> "DECISION_ALLOW", r |-> r])
                    /\ UNCHANGED <<calls, used>>

\* A crash after INTENT / dispatch: no DECISION is ever written for the request, and nothing re-dispatches it.
Crash(r) == /\ phase[r] \in {"intent", "dispatched"}
            /\ phase' = [phase EXCEPT ![r] = "orphan"]
            /\ UNCHANGED <<log, calls, used>>

Next == \E r \in Requests : Admit(r) \/ Replay(r) \/ Block(r) \/ WriteIntent(r) \/ IntentAppendFails(r)
                            \/ CallProvider(r) \/ WriteDecision(r) \/ Crash(r)

Spec == Init /\ [][Next]_vars

TypeOK == /\ phase \in [Requests -> Phases] /\ calls \in [Requests -> Nat] /\ used \subseteq Nonces

HasIntentBefore(i, r) == \E j \in 1..(i - 1) : log[j] = [t |-> "INTENT", r |-> r]

\* No provider call without a logged INTENT (the v7 fail-closed rule).
NoCallWithoutIntent == \A r \in Requests : calls[r] > 0 => \E i \in 1..Len(log) : log[i] = [t |-> "INTENT", r |-> r]

\* An ALLOW decision always has an earlier INTENT (the verifier's MISSING_INTENT failure cannot occur on a chain this process writes).
AllowHasIntent == \A i \in 1..Len(log) : log[i].t = "DECISION_ALLOW" => HasIntentBefore(i, log[i].r)

\* At most one DECISION per request.
OneDecision == \A r \in Requests :
    Cardinality({i \in 1..Len(log) : log[i].r = r /\ log[i].t \in {"DECISION_ALLOW", "DECISION_BLOCK"}}) <= 1

\* The provider is called at most once per nonce, across all requests that carry it.
ProviderOncePerNonce == \A n \in Nonces :
    \A r1, r2 \in {r \in Requests : NonceOf[r] = n} : (calls[r1] > 0 /\ calls[r2] > 0) => r1 = r2

\* A refused request never reached the provider.
RefusedNeverCalled == \A r \in Requests : phase[r] = "refused" => calls[r] = 0

\* Each request is dispatched at most once.
AtMostOneCallPerRequest == \A r \in Requests : calls[r] <= 1
=============================================================================
