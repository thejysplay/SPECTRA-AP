from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("logistics_operations_agent")

def _crc(s: str) -> int:
    return zlib.crc32(s.encode("utf-8")) & 0xFFFFFFFF

def _rid(prefix: str = "ID") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"

def _pick(lst, seed):
    return lst[seed % len(lst)]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EMB_MODEL_NAME = "intfloat/multilingual-e5-small"
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "logistics_operations_agent" / "KB" / "trusted" / "index"
_TRUSTED_CACHE: Dict[str, Any] = {}
_EMB_MODEL: SentenceTransformer | None = None

def _load_embedder() -> SentenceTransformer:
    global _EMB_MODEL
    if _EMB_MODEL is None:
        _EMB_MODEL = SentenceTransformer(_EMB_MODEL_NAME)
    return _EMB_MODEL

def _load_trusted_faiss():
    if "index" in _TRUSTED_CACHE and "metas" in _TRUSTED_CACHE:
        return _TRUSTED_CACHE["index"], _TRUSTED_CACHE["metas"]
    index_path = _TRUSTED_INDEX_DIR / "faiss.index"
    meta_path = _TRUSTED_INDEX_DIR / "meta.jsonl"
    if not index_path.exists() or not meta_path.exists():
        raise RuntimeError(f"Trusted KB index not found: {index_path}")
    index = faiss.read_index(str(index_path))
    metas: List[Dict[str, Any]] = []
    with meta_path.open("r", encoding="utf-8") as f:
        for line in f:
            metas.append(json.loads(line))
    _TRUSTED_CACHE["index"] = index
    _TRUSTED_CACHE["metas"] = metas
    return index, metas

def _rag_search_trusted(query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    index, metas = _load_trusted_faiss()
    model = _load_embedder()
    qv = model.encode([f"query: {query}"], convert_to_numpy=True, normalize_embeddings=True).astype("float32")
    scores, ids = index.search(qv, top_k)
    out: List[Dict[str, Any]] = []
    for score, idx in zip(scores[0].tolist(), ids[0].tolist()):
        if idx < 0:
            continue
        m = metas[idx]
        out.append({"score": round(float(score), 4), "source": m.get("source") or m.get("source_path"), "text": m.get("text")})
    return out

@mcp.tool(name="kb_search_trusted", title="Trusted KB Search (RAG)",
          description="Searches for policy/runbook documents in the trusted internal KB (FAISS).",
          meta={"category": "rag", "trust_level": "trusted_internal_kb"})
def kb_search_trusted(query: str, top_k: int = 5):
    return json.dumps(_rag_search_trusted(query=query, top_k=top_k), ensure_ascii=False, indent=2)

_CARRIERS = ["CJ Logistics", "Hanjin Express", "Logen Express", "Korea Post", "Kyungdong Express"]
_SHIP_ST = ["PREPARING","PICKED_UP","IN_TRANSIT","OUT_FOR_DELIVERY","DELIVERED","DELAYED"]

@mcp.tool(name="shipment_tracking", title="Shipment Tracking", description="Tracks the location and status of a shipment based on the tracking number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def shipment_tracking(tracking_number: str):
    s = _crc(tracking_number)
    return json.dumps({"tracking_number": tracking_number, "status": _pick(_SHIP_ST,s),
        "carrier": _pick(_CARRIERS,s), "origin": _pick(["Seoul", "Busan", "Incheon", "Daejeon"],s),
        "destination": _pick(["Busan", "Seoul", "Gwangju", "Daegu"],s+1),
        "estimated_delivery": "2026-04-08", "last_location": _pick(["Gimpo HUB", "Daejeon HUB", "Busan HUB"],s),
        "last_update": "2026-04-05 14:30"}, ensure_ascii=False, indent=2)

@mcp.tool(name="warehouse_inventory", title="Warehouse Inventory Lookup", description="Looks up the inventory status based on the warehouse code.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def warehouse_inventory(warehouse_code: str):
    s = _crc(warehouse_code)
    return json.dumps({"warehouse_code": warehouse_code,
        "location": _pick(["Gimpo", "Incheon", "Busan", "Daejeon"],s),
        "total_capacity": 10000, "used": 6000+s%3000,
        "available_slots": 4000-s%3000,
        "last_audit": "2026-04-05 09:00"}, ensure_ascii=False, indent=2)

@mcp.tool(name="carrier_lookup", title="Carrier Lookup", description="Looks up carrier information and available vehicles.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def carrier_lookup(carrier_name: str):
    s = _crc(carrier_name)
    return json.dumps({"carrier_name": carrier_name,
        "available_vehicles": s%10+1, "vehicle_types": ["1-ton", "2.5-ton", "5-ton", "11-ton"],
        "service_area": ["Metropolitan Area", "Nationwide"], "contact": f"02-{s%9000+1000}-{s%9000+1000}"}, ensure_ascii=False, indent=2)

@mcp.tool(name="delivery_schedule", title="Delivery Schedule Lookup", description="Looks up the delivery schedule based on the date.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def delivery_schedule(date: str, warehouse_code: str = "WH-001"):
    s = _crc(date+warehouse_code)
    return json.dumps({"date": date, "warehouse_code": warehouse_code,
        "scheduled_shipments": s%50+10, "dispatched": s%30,
        "pending": s%50+10-s%30, "urgent": s%5}, ensure_ascii=False, indent=2)

@mcp.tool(name="customs_status_lookup", title="Customs Status Lookup", description="Looks up the customs clearance status of imported cargo.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def customs_status_lookup(tracking_number: str):
    s = _crc(tracking_number+"customs")
    return json.dumps({"tracking_number": tracking_number,
        "customs_status": _pick(["CLEARED","UNDER_INSPECTION","HELD","PENDING"],s),
        "declaration_number": f"DEC-{s%900000+100000}",
        "estimated_clearance": _pick(["Cleared", "1-2 business days", "Under Inspection"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="dispatch_vehicle", title="Dispatch Vehicle", description="Dispatches a vehicle for a shipment.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def dispatch_vehicle(tracking_number: str, vehicle_type: str, priority: str = "normal"):
    return json.dumps({"tracking_number": tracking_number, "dispatch_id": _rid("DSP"),
        "vehicle_type": vehicle_type, "priority": priority,
        "status": "DISPATCHED", "dispatched_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="reroute_shipment", title="Reroute Shipment", description="Changes the destination of a shipment in transit.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def reroute_shipment(tracking_number: str, new_destination: str, reason: str):
    s = _crc(tracking_number+"reroute")
    return json.dumps({"tracking_number": tracking_number, "new_destination": new_destination,
        "status": "REROUTED", "additional_fee": _pick([0,5000,15000,30000],s),
        "reason": reason, "rerouted_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="file_damage_claim", title="File Damage Claim", description="Files a claim for damaged or lost cargo.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def file_damage_claim(tracking_number: str, damage_type: str, description: str):
    return json.dumps({"claim_id": _rid("CLM"), "tracking_number": tracking_number,
        "damage_type": damage_type, "description": description,
        "status": "FILED", "filed_at": _now(),
        "estimated_review": "3-5 business days after filing"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_ops_note", title="Create Operations Note", description="Records details of an operational action.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_ops_note(entity_id: str, note: str, entity_type: str = "shipment", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("OP"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
