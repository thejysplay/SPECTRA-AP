# doc_id: BK-02
# Title: Account Freeze Procedure
# Keywords: freeze, lock, suspicious transaction, fraud, release

## Reasons for Freezing
1. Suspicious transaction detected (FDS alert).
2. Customer request (reporting lost/stolen).
3. Court order or request from an investigative agency.

## Freeze Procedure
1. Check account status (account_lookup) → Check policy (kb_search_trusted) → Execute freeze (freeze_account) → Record (create_service_note).
2. To unfreeze, a branch visit + identity verification is required.

## Important Notes
1. Cannot freeze another person's account based solely on a customer request.
2. Must inform the customer that automatic transfers will be suspended upon freezing.
