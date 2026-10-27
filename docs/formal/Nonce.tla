------------------------------- MODULE Nonce -------------------------------
(* Single-use artifacts with a Redis restart barrier (docs/protocol/QODIQA-PROTOCOL.md, replay: REPLAY_DETECTED and
   REPLAY_STATE_UNPROVABLE). The worst case is modelled: a restart loses the whole nonce store. After a restart at time B, an
   artifact issued no later than B + Skew whose nonce cannot be proven unused is refused. An artifact can be presented only once the
   clock has reached its issue time minus Skew (it cannot be used before it exists).
   Model scope: time is a small integer; one store; no clock drift beyond Skew; no persistence modelled (the production AOF
   requirement shrinks the loss window, it is not assumed here). *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Artifacts, IssuedAt, NonceOf, Skew, MaxTime
CONSTANT UseBarrier         \* TRUE = the real rule; FALSE = negative control

VARIABLES clock, store, barrier, accepted

vars == <<clock, store, barrier, accepted>>

ModelNonceOf == [a \in Artifacts |-> IF a = "a3" THEN "n2" ELSE "n1"]
ModelIssuedAt == [a \in Artifacts |-> IF a = "a1" THEN 0 ELSE IF a = "a2" THEN 1 ELSE 3]

Init == /\ clock = 0 /\ store = {} /\ barrier = -1 /\ accepted = <<>>

Tick == /\ clock < MaxTime /\ clock' = clock + 1 /\ UNCHANGED <<store, barrier, accepted>>

\* Redis restart: the store is lost and the barrier moves to now.
Restart == /\ barrier' = clock /\ store' = {} /\ UNCHANGED <<clock, accepted>>

Presentable(a) == IssuedAt[a] <= clock + Skew

Accept(a) == /\ Presentable(a)
             /\ NonceOf[a] \notin store
             /\ ~(UseBarrier /\ barrier >= 0 /\ IssuedAt[a] <= barrier + Skew)
             /\ store' = store \cup {NonceOf[a]}
             /\ accepted' = Append(accepted, a)
             /\ UNCHANGED <<clock, barrier>>

Next == Tick \/ Restart \/ \E a \in Artifacts : Accept(a)

Spec == Init /\ [][Next]_vars

\* Safety: no nonce is accepted twice, even across restarts.
NoReplay == \A i, j \in 1..Len(accepted) : (i /= j) => NonceOf[accepted[i]] /= NonceOf[accepted[j]]
=============================================================================
