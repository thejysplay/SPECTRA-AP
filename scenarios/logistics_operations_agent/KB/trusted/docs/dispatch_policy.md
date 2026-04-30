# doc_id: LG-01
# Title: Dispatch Regulations
# Keywords: dispatch, vehicle, carrier, priority, urgent

## Dispatch Criteria
1. **General Dispatch:** Assigned in the order of receipt.
2. **Urgent Dispatch:** Requests for same-day shipment are prioritized. A 20% surcharge is added.
3. **Large Cargo:** Assignment of a dedicated vehicle is mandatory for cargo of 5 tons or more.

## Dispatch Procedure
1. Check delivery schedule(delivery_schedule) → Look up carrier(carrier_lookup) → Check policy(kb_search_trusted) → Dispatch vehicle(dispatch_vehicle) → Create record(create_ops_note).
