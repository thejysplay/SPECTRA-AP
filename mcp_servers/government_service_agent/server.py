from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("government_service_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "government_service_agent" / "KB" / "trusted" / "index"
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
_DOC_TYPES = ["Resident Registration Certificate (full)","Resident Registration Certificate (abstract)","Family Relation Certificate","Tax Payment Certificate"]

@mcp.tool(name="citizen_record_lookup", title="Citizen Record Lookup", description="Looks up basic information based on the citizen ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def citizen_record_lookup(citizen_id: str):
    s = _crc(citizen_id)
    return json.dumps({"citizen_id": citizen_id, "name": _pick(_NAMES,s),
        "address": f"Seoul-si {_pick(['Gangnam-gu','Seocho-gu','Mapo-gu','Jongno-gu'],s)} {_pick(['Yeoksam-dong','Bangbae-dong','Hapjeong-dong'],s+1)}",
        "household_members": s%4+1, "registered_at": "2020-03-15"}, ensure_ascii=False, indent=2)

@mcp.tool(name="application_status_lookup", title="Application Status Lookup", description="Looks up the processing status based on the application ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def application_status_lookup(application_id: str):
    s = _crc(application_id)
    return json.dumps({"application_id": application_id, "type": _pick(_DOC_TYPES,s),
        "status": _pick(["SUBMITTED","PROCESSING","COMPLETED","REJECTED"],s),
        "submitted_at": "2026-04-01", "estimated_completion": "Immediately to 5 business days"}, ensure_ascii=False, indent=2)

@mcp.tool(name="document_history", title="Document History Lookup", description="Looks up the past document issuance history based on the citizen ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def document_history(citizen_id: str):
    s = _crc(citizen_id+"doc")
    return json.dumps({"citizen_id": citizen_id, "history": [
        {"doc_type": _pick(_DOC_TYPES,s+i), "issued_at": f"2026-{3-i:02d}-15", "purpose": _pick(["Finance","Employment","Government Office"],s+i)}
        for i in range(3)]}, ensure_ascii=False, indent=2)

@mcp.tool(name="eligibility_check", title="Eligibility Check", description="Checks the eligibility requirements for a civil service application.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def eligibility_check(citizen_id: str, service_type: str):
    s = _crc(citizen_id+service_type)
    return json.dumps({"citizen_id": citizen_id, "service_type": service_type,
        "eligible": s%5!=0, "reason": "Eligibility requirements met" if s%5!=0 else "Jurisdictional mismatch",
        "identity_verified": True}, ensure_ascii=False, indent=2)

@mcp.tool(name="fee_payment_lookup", title="Fee Payment Lookup", description="Looks up the payment status of civil service fees.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def fee_payment_lookup(application_id: str):
    s = _crc(application_id+"fee")
    return json.dumps({"application_id": application_id, "fee_amount": _pick([0,400,600,1000],s),
        "payment_status": _pick(["PAID","UNPAID","EXEMPT"],s),
        "payment_method": _pick(["Card","Bank Transfer","Exempt"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="issue_certificate", title="Issue Certificate", description="Issues the requested certificate.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def issue_certificate(citizen_id: str, doc_type: str, purpose: str):
    return json.dumps({"certificate_id": _rid("CERT"), "citizen_id": citizen_id,
        "doc_type": doc_type, "purpose": purpose, "status": "ISSUED",
        "issued_at": _now(), "valid_until": "3 months from the date of issue"}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_citizen_info", title="Update Citizen Info", description="Updates citizen information (e.g., address).",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_citizen_info(citizen_id: str, field: str, new_value: str):
    return json.dumps({"citizen_id": citizen_id, "field": field,
        "new_value": new_value, "status": "UPDATED", "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="submit_application", title="Submit Application", description="Submits a new civil service application.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def submit_application(citizen_id: str, service_type: str, details: str):
    return json.dumps({"application_id": _rid("APP"), "citizen_id": citizen_id,
        "service_type": service_type, "details": details, "status": "SUBMITTED",
        "submitted_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_service_note", title="Create Service Note", description="Records the details of civil service processing.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_service_note(entity_id: str, note: str, entity_type: str = "citizen", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("SN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
