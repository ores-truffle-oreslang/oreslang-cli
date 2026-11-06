-------------------- MODULE MergeAssurancePublicCanaryV1 --------------------
EXTENDS Naturals
\* SOURCE-FREE public security policy reference. Not compiler or private source.
CONSTANTS HeadA, HeadB, AllowStaleReview, AllowZeroStep, AllowProtectionBypass
ASSUME HeadA # HeadB
VARIABLES head, reviewState, approvedHead, ciHead, ciSteps, ciGreen,
          branchProtected, noBypass, merged, mergeWasAuthorized
vars == <<head, reviewState, approvedHead, ciHead, ciSteps, ciGreen,
          branchProtected, noBypass, merged, mergeWasAuthorized>>

Init ==
  /\ head = HeadA
  /\ reviewState = "NONE"
  /\ approvedHead = "none"
  /\ ciHead = "none"
  /\ ciSteps = 0
  /\ ciGreen = FALSE
  /\ branchProtected = FALSE
  /\ noBypass = FALSE
  /\ merged = FALSE
  /\ mergeWasAuthorized = FALSE

CurrentApproval == (reviewState = "APPROVED") /\ (approvedHead = head)
ExecutedExactHeadCI == (ciHead = head) /\ ciGreen /\ (ciSteps > 0)
ProtectedNoBypass == branchProtected /\ noBypass
StrictGate == CurrentApproval /\ ExecutedExactHeadCI /\ ProtectedNoBypass

\* Three mutation flags exist only in the candidate; NEVER in the invariant.
CandidateGate ==
  /\ reviewState = "APPROVED"
  /\ (approvedHead = head \/ AllowStaleReview)
  /\ ciHead = head
  /\ ciGreen
  /\ (ciSteps > 0 \/ AllowZeroStep)
  /\ (ProtectedNoBypass \/ AllowProtectionBypass)

ApproveCurrent ==
  /\ ~merged
  /\ reviewState' = "APPROVED"
  /\ approvedHead' = head
  /\ UNCHANGED <<head, ciHead, ciSteps, ciGreen, branchProtected,
                 noBypass, merged, mergeWasAuthorized>>
RequestChanges ==
  /\ ~merged
  /\ reviewState' = "CHANGES_REQUESTED"
  /\ UNCHANGED <<head, approvedHead, ciHead, ciSteps, ciGreen,
                 branchProtected, noBypass, merged, mergeWasAuthorized>>
DismissReview ==
  /\ ~merged
  /\ reviewState' = "DISMISSED"
  /\ UNCHANGED <<head, approvedHead, ciHead, ciSteps, ciGreen,
                 branchProtected, noBypass, merged, mergeWasAuthorized>>
NewHead ==
  /\ ~merged
  /\ head' = IF head = HeadA THEN HeadB ELSE HeadA
  /\ UNCHANGED <<reviewState, approvedHead, ciHead, ciSteps, ciGreen,
                 branchProtected, noBypass, merged, mergeWasAuthorized>>
RunExecutedCI ==
  /\ ~merged
  /\ ciHead' = head
  /\ ciSteps' = 2
  /\ ciGreen' = TRUE
  /\ UNCHANGED <<head, reviewState, approvedHead, branchProtected,
                 noBypass, merged, mergeWasAuthorized>>
\* Adversarial: a green label on an actually zero-step job.
ForgeZeroStepGreen ==
  /\ ~merged
  /\ ciHead' = head
  /\ ciSteps' = 0
  /\ ciGreen' = TRUE
  /\ UNCHANGED <<head, reviewState, approvedHead, branchProtected,
                 noBypass, merged, mergeWasAuthorized>>
EnableProtection ==
  /\ ~merged
  /\ branchProtected' = TRUE
  /\ noBypass' = TRUE
  /\ UNCHANGED <<head, reviewState, approvedHead, ciHead, ciSteps,
                 ciGreen, merged, mergeWasAuthorized>>
DisableProtection ==
  /\ ~merged
  /\ branchProtected' = FALSE
  /\ noBypass' = FALSE
  /\ UNCHANGED <<head, reviewState, approvedHead, ciHead, ciSteps,
                 ciGreen, merged, mergeWasAuthorized>>
Merge ==
  /\ ~merged
  /\ CandidateGate
  /\ merged' = TRUE
  /\ mergeWasAuthorized' = StrictGate
  /\ UNCHANGED <<head, reviewState, approvedHead, ciHead, ciSteps,
                 ciGreen, branchProtected, noBypass>>
Finished == merged /\ UNCHANGED vars
Next ==
  \/ ApproveCurrent \/ RequestChanges \/ DismissReview \/ NewHead
  \/ RunExecutedCI \/ ForgeZeroStepGreen \/ EnableProtection
  \/ DisableProtection \/ Merge \/ Finished
Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ head \in {HeadA, HeadB}
  /\ approvedHead \in {HeadA, HeadB, "none"}
  /\ reviewState \in {"NONE", "APPROVED", "CHANGES_REQUESTED", "DISMISSED"}
  /\ ciHead \in {HeadA, HeadB, "none"}
  /\ ciSteps \in {0, 2}
  /\ ciGreen \in BOOLEAN
  /\ branchProtected \in BOOLEAN
  /\ noBypass \in BOOLEAN
  /\ merged \in BOOLEAN
  /\ mergeWasAuthorized \in BOOLEAN
NoUnsafeMerge == merged => mergeWasAuthorized
=============================================================================
