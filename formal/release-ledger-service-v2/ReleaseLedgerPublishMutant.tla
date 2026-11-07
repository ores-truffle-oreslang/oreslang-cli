---------------------- MODULE ReleaseLedgerPublishMutant ----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* BOUNDED abstract service model; NOT a proof of PostgreSQL, clocks,
\* network, signatures or independent release authorization.
Requests == {"a", "b", "c", "d", "e", "f"}
Int(r) ==
  CASE r = "a" -> [sequence |-> 1, previous |-> "Z",
                    policy |-> 8, repo |-> "cli", digest |-> "A", nonce |-> "na"]
    [] r = "b" -> [sequence |-> 1, previous |-> "Z",
                    policy |-> 9, repo |-> "cli", digest |-> "B", nonce |-> "nb"]
    [] r = "c" -> [sequence |-> 2, previous |-> "A",
                    policy |-> 7, repo |-> "cli", digest |-> "C", nonce |-> "nc"]
    [] r = "d" -> [sequence |-> 2, previous |-> "A",
                    policy |-> 10, repo |-> "cli", digest |-> "D", nonce |-> "nd"]
    [] r = "e" -> [sequence |-> 1, previous |-> "Z",
                    policy |-> 8, repo |-> "other", digest |-> "E", nonce |-> "ne"]
    [] OTHER -> [sequence |-> 2, previous |-> "A",
                    policy |-> 9, repo |-> "cli", digest |-> "F", nonce |-> "na"]

VARIABLES highWater, policyFloor, lastDigest, events, usedNonces,
          stage, acknowledgement, releaseAuthorized

vars == <<highWater, policyFloor, lastDigest, events, usedNonces,
           stage, acknowledgement, releaseAuthorized>>

Init ==
  /\ highWater = 0
  /\ policyFloor = 0
  /\ lastDigest = "Z"
  /\ events = <<>>
  /\ usedNonces = {}
  /\ stage = [r \in Requests |-> "fresh"]
  /\ acknowledgement = [r \in Requests |-> "none"]
  /\ releaseAuthorized = FALSE

Eligible(r) ==
  /\ stage[r] = "fresh"
  /\ Int(r).sequence = highWater + 1
  /\ Int(r).previous = lastDigest
  /\ Int(r).policy >= policyFloor
  /\ Int(r).repo = "cli"
  /\ Int(r).nonce \notin usedNonces

Commit(r) ==
  /\ r \in Requests
  /\ Eligible(r)
  /\ highWater' = highWater + 1
  /\ policyFloor' = Int(r).policy
  /\ lastDigest' = Int(r).digest
  /\ events' = Append(events, [request |-> r, sequence |-> Int(r).sequence,
             policy |-> Int(r).policy, repo |-> Int(r).repo,
             digest |-> Int(r).digest, nonce |-> Int(r).nonce])
  /\ usedNonces' = usedNonces \cup {Int(r).nonce}
  /\ stage' = [stage EXCEPT ![r] = "committed"]
  /\ acknowledgement' = [acknowledgement EXCEPT ![r] = "pending"]
  /\ releaseAuthorized' = TRUE

Reject(r) ==
  /\ r \in Requests
  /\ stage[r] = "fresh"
  /\ ~Eligible(r)
  /\ stage' = [stage EXCEPT ![r] = "denied"]
  /\ UNCHANGED <<highWater, policyFloor, lastDigest, events,
                 usedNonces, acknowledgement, releaseAuthorized>>

Cancel(r) ==
  /\ r \in Requests
  /\ stage[r] = "fresh"
  /\ stage' = [stage EXCEPT ![r] = "cancelled"]
  /\ UNCHANGED <<highWater, policyFloor, lastDigest, events,
                 usedNonces, acknowledgement, releaseAuthorized>>

LoseCommitAcknowledgement(r) ==
  /\ r \in Requests
  /\ stage[r] = "committed"
  /\ acknowledgement[r] = "pending"
  /\ acknowledgement' = [acknowledgement EXCEPT ![r] = "unknown"]
  /\ UNCHANGED <<highWater, policyFloor, lastDigest, events,
                 usedNonces, stage, releaseAuthorized>>

AcknowledgeCommit(r) ==
  /\ r \in Requests
  /\ stage[r] = "committed"
  /\ acknowledgement[r] = "pending"
  /\ acknowledgement' = [acknowledgement EXCEPT ![r] = "confirmed"]
  /\ UNCHANGED <<highWater, policyFloor, lastDigest, events,
                 usedNonces, stage, releaseAuthorized>>

RecoverReceipt(r) ==
  /\ r \in Requests
  /\ stage[r] = "committed"
  /\ acknowledgement[r] = "unknown"
  /\ acknowledgement' = [acknowledgement EXCEPT ![r] = "confirmed"]
  /\ UNCHANGED <<highWater, policyFloor, lastDigest, events,
                 usedNonces, stage, releaseAuthorized>>

Next ==
  \E r \in Requests:
    Commit(r) \/ Reject(r) \/ Cancel(r) \/
    LoseCommitAcknowledgement(r) \/ AcknowledgeCommit(r) \/ RecoverReceipt(r)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ highWater \in 0..2
  /\ policyFloor \in 0..10
  /\ lastDigest \in {"Z","A","B","C","D","E","F"}
  /\ stage \in [Requests -> {"fresh","committed","denied","cancelled"}]
  /\ acknowledgement \in [Requests -> {"none","pending","unknown","confirmed"}]
  /\ usedNonces \subseteq {"na","nb","nc","nd","ne"}
  /\ releaseAuthorized \in BOOLEAN
  /\ highWater = Len(events)

MonotonicSequence ==
  \A i \in 1..Len(events): events[i].sequence = i

NoDuplicateSequence ==
  \A i,j \in 1..Len(events):
    i # j => events[i].sequence # events[j].sequence

NoDuplicateNonce ==
  Cardinality({events[i].nonce: i \in 1..Len(events)}) = Len(events)

NoPolicyRollback ==
  \A i \in 1..(Len(events)-1):
    events[i].policy <= events[i+1].policy

RepositoryFenced ==
  \A i \in 1..Len(events): events[i].repo = "cli"

NoFalseDenial ==
  \A r \in Requests:
    stage[r] = "denied" =>
      \A i \in 1..Len(events): events[i].request # r

AckOnlyForCommitted ==
  \A r \in Requests:
    acknowledgement[r] # "none" => stage[r] = "committed"

NoReleaseAuthorization == releaseAuthorized = FALSE

=============================================================================
