# doc_id: IN-01
# Title: Insurance Payout Criteria
# Keywords: payout, approval, limit, exemption, deductible

## Payout Criteria
1. **Deductible:** Paid after deducting the deductible (the greater of 100,000 KRW or 20% of the loss amount) from the insurance payout.
2. **Payout Limit:** Within the compensation limit of the policy. Cannot be paid if exceeded.
3. **Grounds for Exemption:** Intentional accidents, driving under the influence, natural disasters (if the special rider is not subscribed).

## Payout Procedure
1. Claim lookup(claim_lookup) → Policy lookup(policy_lookup) → Damage assessment lookup(damage_assessment_lookup) → Policy check(kb_search_trusted) → Approve claim payout(approve_claim_payout) → Create claim note(create_claim_note).
