----------------------- MODULE WitnessNoReserveMutant -----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* BOUNDED NON-AUTHORIZING model: a single linearizable witness plus primary.
\* No proof of independent administration, Raft/Paxos, PostgreSQL, network,
\* cryptographic verification, trusted clock or real power-loss durability.
Reqs == {"a","b","c","d","e"}
Claim(r) ==
  CASE r = "a" -> [sequence |-> 1, predecessor |-> "Z", digest |-> "A",
                   policy |-> 8, repository |-> "cli", nonce |-> "na"]
    [] r = "b" -> [sequence |-> 1, predecessor |-> "Z", digest |-> "B",
                   policy |-> 8, repository |-> "cli", nonce |-> "nb"]
    [] r = "c" -> [sequence |-> 2, predecessor |-> "A", digest |-> "C",
                   policy |-> 7, repository |-> "cli", nonce |-> "nc"]
    [] r = "d" -> [sequence |-> 2, predecessor |-> "A", digest |-> "D",
                   policy |-> 9, repository |-> "cli", nonce |-> "nd"]
    [] OTHER  -> [sequence |-> 2, predecessor |-> "A", digest |-> "E",
                   policy |-> 9, repository |-> "other", nonce |-> "ne"]

VARIABLES witnessSeq, primarySeq, generation, witnessDigest, primaryDigest,
  policyFloor, pending, phase, ack, witnessEvents, usedNonces, authorized

vars == <<witnessSeq, primarySeq, generation, witnessDigest, primaryDigest,
  policyFloor, pending, phase, ack, witnessEvents, usedNonces, authorized>>

Init ==
  /\ witnessSeq = 0
  /\ primarySeq = 0
  /\ generation = 0
  /\ witnessDigest = "Z"
  /\ primaryDigest = "Z"
  /\ policyFloor = 0
  /\ pending = "none"
  /\ phase = [r \in Reqs |-> "fresh"]
  /\ ack = [r \in Reqs |-> "none"]
  /\ witnessEvents = <<>>
  /\ usedNonces = {}
  /\ authorized = FALSE

CanReserve(r) ==
  /\ r \in Reqs
  /\ phase[r] = "fresh"
  /\ pending = "none"
  /\ witnessSeq = primarySeq
  /\ witnessDigest = primaryDigest
  /\ Claim(r).sequence = witnessSeq + 1
  /\ Claim(r).predecessor = witnessDigest
  /\ Claim(r).policy >= policyFloor
  /\ Claim(r).repository = "cli"
  /\ Claim(r).nonce \notin usedNonces

Reserve(r) ==
  /\ CanReserve(r)
  /\ pending' = r
  /\ phase' = [phase EXCEPT ![r] = "reserved"]
  /\ UNCHANGED <<witnessSeq,primarySeq,generation,witnessDigest,
    primaryDigest,policyFloor,ack,witnessEvents,usedNonces,authorized>>

PrimaryCommit(r) ==
  /\ r \in Reqs
  \* MUTANT: accept primary COMMIT without any witness reservation
  /\ phase[r] = "fresh"
  /\ primarySeq = witnessSeq
  /\ primaryDigest = witnessDigest
  /\ primarySeq' = primarySeq + 1
  /\ primaryDigest' = Claim(r).digest
  /\ phase' = [phase EXCEPT ![r] = "primary"]
  /\ ack' = [ack EXCEPT ![r] = "pending"]
  /\ UNCHANGED <<witnessSeq,generation,witnessDigest,policyFloor,
    pending,witnessEvents,usedNonces,authorized>>

CommitAckLost(r) ==
  /\ r \in Reqs
  /\ phase[r] = "primary"
  /\ ack[r] = "pending"
  /\ ack' = [ack EXCEPT ![r] = "unknown"]
  /\ UNCHANGED <<witnessSeq,primarySeq,generation,witnessDigest,
    primaryDigest,policyFloor,pending,phase,witnessEvents,usedNonces,
    authorized>>

Finalize(r) ==
  /\ r \in Reqs
  /\ pending = r
  /\ phase[r] = "primary"
  /\ primarySeq = witnessSeq + 1
  /\ primaryDigest = Claim(r).digest
  /\ witnessSeq' = witnessSeq + 1
  /\ witnessDigest' = Claim(r).digest
  /\ generation' = generation + 1
  /\ policyFloor' = Claim(r).policy
  /\ witnessEvents' = Append(witnessEvents,
      [request |-> r, sequence |-> Claim(r).sequence,
       policy |-> Claim(r).policy, nonce |-> Claim(r).nonce])
  /\ usedNonces' = usedNonces \cup {Claim(r).nonce}
  /\ pending' = "none"
  /\ phase' = [phase EXCEPT ![r] = "finalized"]
  /\ ack' = [ack EXCEPT ![r] = "confirmed"]
  /\ UNCHANGED <<primarySeq,primaryDigest,authorized>>

CancelFresh(r) ==
  /\ r \in Reqs
  /\ phase[r] = "fresh"
  /\ phase' = [phase EXCEPT ![r] = "cancelled"]
  /\ UNCHANGED <<witnessSeq,primarySeq,generation,witnessDigest,
    primaryDigest,policyFloor,pending,ack,witnessEvents,usedNonces,
    authorized>>

\* Crashes/partitions cannot undo a PENDING witness reservation or a
\* previously durable primary COMMIT. They are stuttering steps.
CrashOrPartition == UNCHANGED vars

Next ==
  \/ \E r \in Reqs: Reserve(r) \/ PrimaryCommit(r) \/
       CommitAckLost(r) \/ Finalize(r) \/ CancelFresh(r)
  \/ CrashOrPartition

Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ witnessSeq \in 0..2
  /\ primarySeq \in 0..2
  /\ generation \in 0..2
  /\ witnessDigest \in {"Z","A","B","C","D","E"}
  /\ primaryDigest \in {"Z","A","B","C","D","E"}
  /\ policyFloor \in 0..9
  /\ pending \in Reqs \cup {"none"}
  /\ phase \in [Reqs -> {"fresh","reserved","primary","finalized","cancelled"}]
  /\ ack \in [Reqs -> {"none","pending","unknown","confirmed"}]
  /\ usedNonces \subseteq {"na","nb","nc","nd","ne"}
  /\ authorized \in BOOLEAN
  /\ witnessSeq = Len(witnessEvents)

WitnessNeverAheadOfPrimary == witnessSeq <= primarySeq
PrimaryNeverAheadByMoreThanOne == primarySeq <= witnessSeq+1
GenerationIsWitnessSequence == generation = witnessSeq
UnfinalizedPrimaryHasReservation ==
  primarySeq > witnessSeq =>
    (pending # "none" /\ primaryDigest = Claim(pending).digest)
NoDuplicateWitnessSequences ==
  \A i \in 1..Len(witnessEvents):
    witnessEvents[i].sequence = i
NoDuplicateWitnessNonces ==
  Cardinality({witnessEvents[i].nonce: i \in 1..Len(witnessEvents)}) = Len(witnessEvents)
PolicyNeverRollsBack ==
  \A i \in 1..(Len(witnessEvents)-1):
    witnessEvents[i].policy <= witnessEvents[i+1].policy
NoUnwitnessedPublication == authorized = FALSE

=============================================================================
