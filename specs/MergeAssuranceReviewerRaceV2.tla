-------------------- MODULE MergeAssuranceReviewerRaceV2 --------------------
EXTENDS Naturals

\* Public source-free bounded reviewer/race policy model. NOT a private proof.
CONSTANTS HeadA, HeadB, AllowSelfReview, AllowCachedSnapshot, AllowRevokedReview
ASSUME HeadA # HeadB

VARIABLES head, reviewer, reviewState, approvedHead, everApprovedHead,
          ciHead, ciSteps, ciGreen, protectedMain, hasSnapshot, snapshotHead,
          merged, validAtMerge
vars == <<head, reviewer, reviewState, approvedHead, everApprovedHead,
          ciHead, ciSteps, ciGreen, protectedMain, hasSnapshot, snapshotHead,
          merged, validAtMerge>>

Init ==
  /\ head = HeadA
  /\ reviewer = "none"
  /\ reviewState = "NONE"
  /\ approvedHead = "none"
  /\ everApprovedHead = "none"
  /\ ciHead = "none"
  /\ ciSteps = 0
  /\ ciGreen = FALSE
  /\ protectedMain = FALSE
  /\ hasSnapshot = FALSE
  /\ snapshotHead = "none"
  /\ merged = FALSE
  /\ validAtMerge = FALSE

IndependentCurrentReview ==
  /\ reviewState = "APPROVED"
  /\ reviewer = "independent"
  /\ approvedHead = head

ExecutedOriginalHeadCI ==
  /\ ciHead = head
  /\ ciSteps > 0
  /\ ciGreen

StrictGate ==
  /\ IndependentCurrentReview
  /\ ExecutedOriginalHeadCI
  /\ protectedMain

\* Intentionally unsafe proposals for mutation testing ONLY. StrictGate
\* is unchanged for all four model-checker configurations.
CandidateGate ==
  \/ StrictGate
  \/ (AllowSelfReview /\
      reviewState = "APPROVED" /\
      reviewer = "author" /\
      approvedHead = head /\
      ExecutedOriginalHeadCI /\ protectedMain)
  \/ (AllowCachedSnapshot /\ hasSnapshot)
  \/ (AllowRevokedReview /\
      everApprovedHead = head /\
      reviewState \in {"DISMISSED", "CHANGES_REQUESTED"} /\
      ExecutedOriginalHeadCI /\ protectedMain)

ApproveIndependent ==
  /\ ~merged
  /\ reviewer' = "independent"
  /\ reviewState' = "APPROVED"
  /\ approvedHead' = head
  /\ everApprovedHead' = head
  /\ UNCHANGED <<head, ciHead, ciSteps, ciGreen, protectedMain,
                 hasSnapshot, snapshotHead, merged, validAtMerge>>

ApproveSelf ==
  /\ ~merged
  /\ reviewer' = "author"
  /\ reviewState' = "APPROVED"
  /\ approvedHead' = head
  /\ UNCHANGED <<head, everApprovedHead, ciHead, ciSteps, ciGreen,
                 protectedMain, hasSnapshot, snapshotHead, merged, validAtMerge>>

RequestChanges ==
  /\ ~merged
  /\ reviewState' = "CHANGES_REQUESTED"
  /\ UNCHANGED <<head, reviewer, approvedHead, everApprovedHead, ciHead,
                 ciSteps, ciGreen, protectedMain, hasSnapshot, snapshotHead,
                 merged, validAtMerge>>

DismissReview ==
  /\ ~merged
  /\ reviewState' = "DISMISSED"
  /\ UNCHANGED <<head, reviewer, approvedHead, everApprovedHead, ciHead,
                 ciSteps, ciGreen, protectedMain, hasSnapshot, snapshotHead,
                 merged, validAtMerge>>

AdvanceHead ==
  /\ ~merged
  /\ head' = IF head = HeadA THEN HeadB ELSE HeadA
  /\ UNCHANGED <<reviewer, reviewState, approvedHead, everApprovedHead, ciHead,
                 ciSteps, ciGreen, protectedMain, hasSnapshot, snapshotHead,
                 merged, validAtMerge>>

ExecutedRun ==
  /\ ~merged
  /\ ciHead' = head
  /\ ciSteps' = 2
  /\ ciGreen' = TRUE
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 protectedMain, hasSnapshot, snapshotHead, merged, validAtMerge>>

\* Malicious success label with no executed job steps.
ForgedZeroStepRun ==
  /\ ~merged
  /\ ciHead' = head
  /\ ciSteps' = 0
  /\ ciGreen' = TRUE
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 protectedMain, hasSnapshot, snapshotHead, merged, validAtMerge>>

Protect ==
  /\ ~merged
  /\ protectedMain' = TRUE
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 ciHead, ciSteps, ciGreen, hasSnapshot, snapshotHead,
                 merged, validAtMerge>>

Unprotect ==
  /\ ~merged
  /\ protectedMain' = FALSE
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 ciHead, ciSteps, ciGreen, hasSnapshot, snapshotHead,
                 merged, validAtMerge>>

SnapshotQualification ==
  /\ ~merged
  /\ StrictGate
  /\ hasSnapshot' = TRUE
  /\ snapshotHead' = head
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 ciHead, ciSteps, ciGreen, protectedMain, merged, validAtMerge>>

Merge ==
  /\ ~merged
  /\ CandidateGate
  /\ merged' = TRUE
  /\ validAtMerge' = StrictGate
  /\ UNCHANGED <<head, reviewer, reviewState, approvedHead, everApprovedHead,
                 ciHead, ciSteps, ciGreen, protectedMain,
                 hasSnapshot, snapshotHead>>

Finished == merged /\ UNCHANGED vars

Next ==
  \/ ApproveIndependent
  \/ ApproveSelf
  \/ RequestChanges
  \/ DismissReview
  \/ AdvanceHead
  \/ ExecutedRun
  \/ ForgedZeroStepRun
  \/ Protect
  \/ Unprotect
  \/ SnapshotQualification
  \/ Merge
  \/ Finished

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ head \in {HeadA, HeadB}
  /\ reviewer \in {"none", "author", "independent"}
  /\ reviewState \in {"NONE", "APPROVED", "DISMISSED", "CHANGES_REQUESTED"}
  /\ approvedHead \in {HeadA, HeadB, "none"}
  /\ everApprovedHead \in {HeadA, HeadB, "none"}
  /\ ciHead \in {HeadA, HeadB, "none"}
  /\ ciSteps \in {0, 2}
  /\ ciGreen \in BOOLEAN
  /\ protectedMain \in BOOLEAN
  /\ hasSnapshot \in BOOLEAN
  /\ snapshotHead \in {HeadA, HeadB, "none"}
  /\ merged \in BOOLEAN
  /\ validAtMerge \in BOOLEAN

NoUnsafeMerge == merged => validAtMerge
=============================================================================
