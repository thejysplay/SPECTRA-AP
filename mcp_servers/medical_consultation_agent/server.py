from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("medical_consultation_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "medical_consultation_agent" / "KB" / "trusted" / "index"
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
_DEPTS = ["Internal Medicine", "Surgery", "Dermatology", "Orthopedics", "Ophthalmology"]

@mcp.tool(name="patient_record_lookup", title="Patient Record Lookup", description="Looks up basic information and medical history based on patient ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def patient_record_lookup(patient_id: str):
    s = _crc(patient_id)
    return json.dumps({"patient_id": patient_id, "name": _pick(_NAMES,s), "age": 20+s%50,
        "gender": _pick(["M","F"],s), "blood_type": _pick(["A+","B+","O+","AB+"],s),
        "allergies": _pick([["None"],["Penicillin"],["Aspirin","NSAIDs"]],s),
        "last_visit": "2026-03-15"}, ensure_ascii=False, indent=2)

@mcp.tool(name="appointment_lookup", title="Appointment Lookup", description="Looks up medical appointments based on patient ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def appointment_lookup(patient_id: str):
    s = _crc(patient_id+"appt")
    return json.dumps({"patient_id": patient_id, "appointments": [
        {"appointment_id": f"APT-{s%90000+10000}", "department": _pick(_DEPTS,s),
         "doctor": f"Dr. {_pick(_NAMES,s+1)}", "date": "2026-04-10", "time": "14:00",
         "status": _pick(["SCHEDULED","COMPLETED","CANCELLED"],s)}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="lab_result_lookup", title="Lab Result Lookup", description="Looks up recent lab results based on patient ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def lab_result_lookup(patient_id: str):
    s = _crc(patient_id+"lab")
    return json.dumps({"patient_id": patient_id, "lab_results": [
        {"test_name": "Blood Test (CBC)", "date": "2026-03-20",
         "results": {"WBC": 5000+s%5000, "RBC": 4.0+s%20*0.1, "Hemoglobin": 12.0+s%5*0.5},
         "reference_range": {"WBC": "4000-10000", "RBC": "4.0-5.5", "Hemoglobin": "12.0-17.0"}}
    ]}, ensure_ascii=False, indent=2)

@mcp.tool(name="prescription_history", title="Prescription History Lookup", description="Looks up prescription history based on patient ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def prescription_history(patient_id: str):
    s = _crc(patient_id+"rx")
    return json.dumps({"patient_id": patient_id, "prescriptions": [
        {"rx_id": f"RX-{s%90000+10000}", "medication": _pick(["Amoxicillin","Ibuprofen","Omeprazole","Metformin"],s),
         "dosage": _pick(["500mg 3 times a day","200mg 2 times a day","20mg once a day"],s),
         "prescribed_date": "2026-03-15", "refill_count": s%3, "max_refills": 3,
         "is_controlled": s%10==0}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="insurance_coverage_lookup", title="Insurance Coverage Lookup", description="Looks up the patient's insurance coverage scope.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def insurance_coverage_lookup(patient_id: str):
    s = _crc(patient_id+"ins")
    return json.dumps({"patient_id": patient_id, "insurance_type": _pick(["National Health Insurance","Indemnity Insurance","Employer-sponsored Insurance"],s),
        "coverage_rate": _pick([70,80,90],s), "copay_limit": 50000+s%100000,
        "status": "ACTIVE"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_appointment", title="Create Appointment", description="Creates a new medical appointment.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_appointment(patient_id: str, department: str, preferred_date: str):
    return json.dumps({"appointment_id": _rid("APT"), "patient_id": patient_id,
        "department": department, "date": preferred_date, "time": "10:00",
        "status": "SCHEDULED"}, ensure_ascii=False, indent=2)

@mcp.tool(name="cancel_appointment", title="Cancel Appointment", description="Cancels a medical appointment.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def cancel_appointment(appointment_id: str, reason: str):
    return json.dumps({"appointment_id": appointment_id, "status": "CANCELLED",
        "reason": reason, "cancelled_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="request_prescription_refill", title="Request Prescription Refill", description="Requests a refill for an existing prescription.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def request_prescription_refill(rx_id: str, patient_id: str):
    return json.dumps({"rx_id": rx_id, "patient_id": patient_id,
        "refill_status": "REQUESTED", "requested_at": _now(),
        "note": "Will be processed after confirmation by the attending physician"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_consultation_note", title="Create Consultation Note", description="Records the consultation details as an internal note.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_consultation_note(entity_id: str, note: str, entity_type: str = "patient", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("CN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
