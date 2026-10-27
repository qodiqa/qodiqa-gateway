----------------------------- MODULE ActionChain -----------------------------
(* The per-session action ledger (src/core/actions/executor.js, docs/protocol/QODIQA-PROTOCOL.md): action n executes only after
   action n-1 was consumed, a (session, seq) row can exist once (unique key), and prevActionHash is the previous row hash.
   Hashes are abstract: a hash is the pair <<seq, prevHash>>, so two different histories can never collide in the model.
   Model scope: one session, several concurrent callers racing for the same sequence numbers; no failure of the store. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Callers, MaxSeq
CONSTANT EnforceOrder         \* FALSE = negative control (no n-1 check)

VARIABLES ledger, pending      \* ledger: sequence of [seq, prev, hash]; pending[c]: the seq caller c is attempting, 0 = idle

vars == <<ledger, pending>>

HashOf(seq, prev) == <<seq, prev>>

Init == /\ ledger = <<>> /\ pending = [c \in Callers |-> 0]

Begin(c, n) == /\ pending[c] = 0 /\ n \in 1..MaxSeq
               /\ pending' = [pending EXCEPT ![c] = n] /\ UNCHANGED ledger

PrevHash(n) == IF n = 1 \/ Len(ledger) = 0 THEN "none" ELSE ledger[Len(ledger)].hash

\* The insert is one atomic step (a single SQL transaction with a unique key).
Commit(c) == LET n == pending[c] IN
    /\ n > 0
    /\ \A i \in 1..Len(ledger) : ledger[i].seq /= n                 \* unique (session, seq)
    /\ (EnforceOrder => (n = Len(ledger) + 1))                      \* n-1 already consumed
    /\ ledger' = Append(ledger, [seq |-> n, prev |-> PrevHash(n), hash |-> HashOf(n, PrevHash(n))])
    /\ pending' = [pending EXCEPT ![c] = 0]

Reject(c) == /\ pending[c] > 0 /\ pending' = [pending EXCEPT ![c] = 0] /\ UNCHANGED ledger

Next == \E c \in Callers : (\E n \in 1..MaxSeq : Begin(c, n)) \/ Commit(c) \/ Reject(c)

Spec == Init /\ [][Next]_vars

NoDuplicateSeq == \A i, j \in 1..Len(ledger) : i /= j => ledger[i].seq /= ledger[j].seq
Contiguous == \A i \in 1..Len(ledger) : ledger[i].seq = i
HashLinked == \A i \in 1..Len(ledger) : ledger[i].prev = IF i = 1 THEN "none" ELSE ledger[i - 1].hash
=============================================================================
