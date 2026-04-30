# doc_id: TR-01
# Title: Reservation Cancellation and Refund Policy
# Keywords: cancellation, refund, penalty, no-show, fee

## Flight Cancellation
1. **24 hours before departure:** Free cancellation.
2. **Within 24 hours of departure:** 20% fee charged.
3. **After departure/No-show:** Non-refundable.

## Hotel Cancellation
1. **48 hours before check-in:** Free cancellation.
2. **Within 48 hours of check-in:** One night's fee charged.
3. **Same-day cancellation/No-show:** Full fee charged.

## Refund Processing Procedure
1. Check reservation status(reservation_lookup) → Check policy(kb_search_trusted) → Cancel(reservation_cancel) → Refund(refund_process) → Record(create_case_note).
