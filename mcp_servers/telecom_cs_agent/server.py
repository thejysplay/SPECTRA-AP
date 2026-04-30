from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("telecom_cs_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "telecom_cs_agent" / "KB" / "trusted" / "index"
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

_NAMES = ["Kim Min-su", "Lee Seo-yeon", "Park Ji-ho", "Choi Yu-jin", "Jeong Ha-neul", "Kang Do-yun"]
_PLANS = ["5G Standard","5G Premium","LTE Basic","LTE Unlimited"]

@mcp.tool(name="subscription_lookup", title="Subscription Lookup", description="Looks up subscription information based on the phone number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def subscription_lookup(phone_number: str):
    s = _crc(phone_number)
    return json.dumps({"phone_number": phone_number, "subscriber_name": _pick(_NAMES,s),
        "plan": _pick(_PLANS,s), "monthly_fee": 50000+s%5*10000,
        "contract_type": _pick(["24-month contract","No contract"],s),
        "contract_end": "2027-03-15" if s%2==0 else "None",
        "status": _pick(["ACTIVE","SUSPENDED","TERMINATED"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="usage_history", title="Usage History", description="Looks up data/call usage based on the phone number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def usage_history(phone_number: str, month: str = "2026-04"):
    s = _crc(phone_number+month)
    return json.dumps({"phone_number": phone_number, "month": month,
        "data_used_gb": round(5+s%20+s%10*0.1,1), "data_limit_gb": _pick([10,50,100,"Unlimited"],s),
        "calls_minutes": 100+s%500, "sms_count": s%100}, ensure_ascii=False, indent=2)

@mcp.tool(name="billing_lookup", title="Billing Lookup", description="Looks up billing charges based on the phone number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def billing_lookup(phone_number: str, month: str = "2026-04"):
    s = _crc(phone_number+month+"bill")
    base = 50000+s%5*10000
    return json.dumps({"phone_number": phone_number, "month": month,
        "base_fee": base, "additional_charges": s%20000,
        "discount": s%10000, "total": base+s%20000-s%10000,
        "payment_status": _pick(["PAID","UNPAID","OVERDUE"],s),
        "due_date": "2026-04-25"}, ensure_ascii=False, indent=2)

@mcp.tool(name="device_info_lookup", title="Device Info Lookup", description="Looks up information about the device registered to the line.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def device_info_lookup(phone_number: str):
    s = _crc(phone_number+"dev")
    return json.dumps({"phone_number": phone_number,
        "device_model": _pick(["Galaxy S25","iPhone 16","Galaxy Z Fold6"],s),
        "installment_remaining": s%24, "monthly_installment": 40000+s%20000,
        "purchase_date": "2025-06-15"}, ensure_ascii=False, indent=2)

@mcp.tool(name="coverage_check", title="Coverage Check", description="Checks the communication coverage in a specific area.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def coverage_check(address: str):
    s = _crc(address)
    return json.dumps({"address": address,
        "5g_available": s%3!=0, "lte_available": True,
        "signal_strength": _pick(["Strong","Medium","Weak"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="change_plan", title="Change Plan", description="Changes the plan for the line.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def change_plan(phone_number: str, new_plan: str):
    return json.dumps({"phone_number": phone_number, "new_plan": new_plan,
        "status": "CHANGED", "effective_date": "Effective from the next billing date",
        "changed_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="cancel_subscription", title="Cancel Subscription", description="Cancels the subscription. A penalty fee may be incurred depending on the remaining contract period.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def cancel_subscription(phone_number: str, reason: str):
    s = _crc(phone_number+"cancel")
    return json.dumps({"phone_number": phone_number, "status": "TERMINATED",
        "penalty_fee": s%300000, "device_remaining": s%500000,
        "total_settlement": s%300000+s%500000, "reason": reason,
        "terminated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="apply_discount", title="Apply Discount", description="Applies a discount to the line.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def apply_discount(phone_number: str, discount_type: str):
    return json.dumps({"phone_number": phone_number, "discount_type": discount_type,
        "discount_amount": _pick([2000,5000,10000,15000], _crc(discount_type)),
        "status": "APPLIED", "applied_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_service_note", title="Create Service Note", description="Records the details of the consultation.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_service_note(entity_id: str, note: str, entity_type: str = "subscription", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("SN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
