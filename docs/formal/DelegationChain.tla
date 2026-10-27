--------------------------- MODULE DelegationChain ---------------------------
(* Delegation chains (docs/protocol/DELEGATION.md section 2): rights only shrink down a chain, no agent appears twice, depth is
   bounded by the root maxDepth, and a revoked link invalidates everything below it. The model builds chains one link at a time
   and checks that every reachable chain satisfies the offline rules and that revocation propagates.
   Model scope: classes are a small set; signatures, tools and maxActions are not modelled. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Agents, Classes, MaxDepth
CONSTANT EnforceAttenuation        \* FALSE = negative control

VARIABLES links, revoked          \* links: sequence of [issuer, subject, classes]; revoked: set of link indices

vars == <<links, revoked>>

Init == /\ links = <<>> /\ revoked = {}

AgentsOf(ls) == IF ls = <<>> THEN {} ELSE {ls[1].issuer} \cup {ls[i].subject : i \in 1..Len(ls)}

Root(a, s, cs) == /\ links = <<>> /\ a /= s /\ cs /= {}
                  /\ links' = <<[issuer |-> a, subject |-> s, classes |-> cs]>> /\ UNCHANGED revoked

Child(s, cs) == LET n == Len(links) IN
    /\ n >= 1 /\ n < MaxDepth
    /\ s \notin AgentsOf(links)                                       \* no agent twice: also rules out a cycle
    /\ cs /= {} /\ (EnforceAttenuation => cs \subseteq links[n].classes)
    /\ links' = Append(links, [issuer |-> links[n].subject, subject |-> s, classes |-> cs]) /\ UNCHANGED revoked

Revoke(i) == /\ i \in 1..Len(links) /\ revoked' = revoked \cup {i} /\ UNCHANGED links

Next == \/ \E a, s \in Agents, cs \in SUBSET Classes : Root(a, s, cs)
        \/ \E s \in Agents, cs \in SUBSET Classes : Child(s, cs)
        \/ \E i \in 1..MaxDepth : Revoke(i)

Spec == Init /\ [][Next]_vars

\* A link is usable when neither it nor any ancestor is revoked.
Usable(i) == \A j \in 1..i : j \notin revoked

Attenuation == \A i \in 2..Len(links) : links[i].classes \subseteq links[i - 1].classes
Linkage == \A i \in 2..Len(links) : links[i].issuer = links[i - 1].subject
NoRepeatedAgent == Len(links) = 0 \/ Cardinality(AgentsOf(links)) = Len(links) + 1
DepthBound == Len(links) <= MaxDepth
\* What a holder may exercise at the leaf is a subset of what the root granted, whatever happened in between.
LeafWithinRoot == Len(links) = 0 \/ links[Len(links)].classes \subseteq links[1].classes
\* Revocation propagates: if link j is revoked, no link at or below j is usable.
RevocationPropagates == \A j \in revoked : \A i \in j..Len(links) : ~Usable(i)
=============================================================================
