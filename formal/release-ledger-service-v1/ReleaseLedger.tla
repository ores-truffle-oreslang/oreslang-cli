------------------------ MODULE ReleaseLedger ------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Bounded abstract model of a single repository-scoped PostgreSQL ledger.
\* Authenticated clients produce immutable Claim records. A transaction
\* serializes Commit or records a rejected request nonce. No publisher exists.
\*
\* THIS SPECIFICATION IS AUTHORED, NOT TLC-MODEL-CHECKED IN CI.
\* Operators must provide a finite Clients set, Claim function and Repo.

CONSTANTS Clients, Claim, Repo
VARIABLES highWater, policyFloor, events, usedNonces, seenRequests, authorized

vars == <<highWater, policyFloor, events, usedNonces, seenRequests, authorized>>

Init ==
  /\ highWater = 0
  /\ policyFloor = 0
  /\ events = <<>>
  /\ usedNonces = {}
  /\ seenRequests = {}
  /\ authorized = FALSE

Eligible(c) ==
  /\ Claim[c].sequence = highWater + 1
  /\ Claim[c].repository = Repo
  /\ Claim[c].policy >= policyFloor
  /\ Claim[c].nonce \notin usedNonces
  /\ Claim[c].nonce \notin seenRequests
  /\ Claim[c].previous = IF highWater = 0 THEN "ZERO"
                           ELSE events[highWater].digest

Commit(c) ==
  /\ c \in Clients
  /\ Eligible(c)
  /\ highWater' = highWater + 1
  /\ policyFloor' = Claim[c].policy
  /\ events' = Append(events,
       [client |-> c, sequence |-> Claim[c].sequence,
        policy |-> Claim[c].policy, digest |-> Claim[c].digest,
        nonce |-> Claim[c].nonce])
  /\ usedNonces' = usedNonces \cup {Claim[c].nonce}
  /\ seenRequests' = seenRequests \cup {Claim[c].nonce}
  /\ authorized' = FALSE

Reject(c) ==
  /\ c \in Clients
  /\ Claim[c].nonce \notin seenRequests
  /\ ~Eligible(c)
  /\ seenRequests' = seenRequests \cup {Claim[c].nonce}
  /\ UNCHANGED <<highWater, policyFloor, events, usedNonces, authorized>>

Next == \E c \in Clients: Commit(c) \/ Reject(c)
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ highWater \in Nat
  /\ policyFloor \in Nat
  /\ events \in Seq([client: Clients, sequence: Nat,
                      policy: Nat, digest: STRING, nonce: STRING])
  /\ usedNonces \subseteq STRING
  /\ seenRequests \subseteq STRING
  /\ authorized \in BOOLEAN

OneSequencePerEvent == highWater = Len(events)
NoDuplicateSequence ==
  \A i,j \in 1..Len(events):
    (i # j) => events[i].sequence # events[j].sequence
NoDuplicateNonce ==
  Cardinality({events[i].nonce: i \in 1..Len(events)}) = Len(events)
MonotonicSequence ==
  \A i \in 1..Len(events): events[i].sequence = i
MonotonicPolicy ==
  \A i \in 1..(Len(events)-1): events[i].policy <= events[i+1].policy
NoReleaseAuthorization == authorized = FALSE

=============================================================================
