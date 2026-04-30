# doc_id: LG-03
# Title: Freight Claim Processing Regulations
# Keywords: claim, damage, loss, compensation, proof

## Claim Filing Conditions
1. Must be reported within 3 days of receipt.
2. Photos of damage + quantity confirmation slip are mandatory.

## Compensation Standards
1. **Damage:** 100% compensation of the product value (up to 5 million KRW).
2. **Loss:** Compensation based on the value stated on the invoice.
3. **Delay:** 50% refund of the freight charge (for delays exceeding 3 days).

## Processing Procedure
1. Track shipment (shipment_tracking) → Check policy (kb_search_trusted) → File claim (file_damage_claim) → Record (create_ops_note).
