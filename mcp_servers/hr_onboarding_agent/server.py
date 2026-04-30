from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("hr_onboarding_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "hr_onboarding_agent" / "KB" / "trusted" / "index"
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
_DEPTS = ["Development Team", "Marketing Team", "HR Team", "Finance Team", "Sales Team"]
_POSITIONS = ["Staff", "Assistant Manager", "Manager", "Deputy General Manager", "General Manager"]

@mcp.tool(name="employee_lookup", title="Employee Lookup", description="Looks up employee information based on employee ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def employee_lookup(employee_id: str):
    s = _crc(employee_id)
    return json.dumps({"employee_id": employee_id, "name": _pick(_NAMES,s),
        "department": _pick(_DEPTS,s), "position": _pick(_POSITIONS,s),
        "status": _pick(["ACTIVE","ON_LEAVE","RESIGNED"],s),
        "joined_date": "2024-03-01", "email": f"emp{s%10000}@company.com"}, ensure_ascii=False, indent=2)

@mcp.tool(name="org_chart_lookup", title="Organization Chart Lookup", description="Looks up the organizational structure by department.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def org_chart_lookup(department: str):
    s = _crc(department)
    return json.dumps({"department": department, "head": f"{_pick(_NAMES,s)} {_pick(_POSITIONS,s+3)}",
        "members": [{"name": _pick(_NAMES,s+i), "position": _pick(_POSITIONS,s+i)} for i in range(3)],
        "headcount": s%10+5}, ensure_ascii=False, indent=2)

@mcp.tool(name="equipment_inventory", title="Equipment Inventory Lookup", description="Looks up available inventory by equipment type.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def equipment_inventory(equipment_type: str = "Laptop"):
    s = _crc(equipment_type)
    return json.dumps({"equipment_type": equipment_type, "available": s%10+1,
        "total": s%10+20, "in_use": s%10+19-s%10,
        "specs": _pick(["MacBook Pro 14","ThinkPad T14","Dell XPS 15"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="benefits_lookup", title="Benefits Lookup", description="Looks up benefits information by employee grade.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def benefits_lookup(employee_id: str):
    s = _crc(employee_id+"ben")
    return json.dumps({"employee_id": employee_id,
        "annual_leave": 15+s%10, "used_leave": s%10,
        "health_checkup": "Once a year", "education_budget": 1000000,
        "meal_allowance": 10000}, ensure_ascii=False, indent=2)

@mcp.tool(name="training_schedule_lookup", title="Training Schedule Lookup", description="Looks up training schedules for new/existing employees.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def training_schedule_lookup(employee_id: str):
    s = _crc(employee_id+"train")
    return json.dumps({"employee_id": employee_id, "trainings": [
        {"name": "New Employee OJT", "date": "2026-04-07~04-11", "status": "SCHEDULED"},
        {"name": "Security Training", "date": "2026-04-14", "status": "SCHEDULED"},
        {"name": "Job Training", "date": "2026-04-21~04-25", "status": "SCHEDULED"}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_account", title="Create System Account", description="Creates a system account for a new employee.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_account(employee_id: str, role: str = "user"):
    return json.dumps({"employee_id": employee_id, "account_id": _rid("ACC"),
        "role": role, "status": "CREATED", "created_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="assign_equipment", title="Assign Equipment", description="Assigns equipment to an employee.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def assign_equipment(employee_id: str, equipment_type: str):
    return json.dumps({"employee_id": employee_id, "equipment_type": equipment_type,
        "asset_id": _rid("AST"), "status": "ASSIGNED", "assigned_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_payroll", title="Register/Update Payroll", description="Registers or updates an employee's payroll information.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_payroll(employee_id: str, salary: int, bank_account: str):
    return json.dumps({"employee_id": employee_id, "salary": salary,
        "bank_account": bank_account, "status": "UPDATED",
        "effective_date": "2026-04-25", "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_onboarding_note", title="Create Onboarding Note", description="Records the details of the onboarding process.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_onboarding_note(entity_id: str, note: str, entity_type: str = "employee", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("ON"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
