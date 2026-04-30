from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("education_admin_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "education_admin_agent" / "KB" / "trusted" / "index"
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
_MAJORS = ["Computer Science","Business Administration","Electrical Engineering","Psychology","Chemistry"]

@mcp.tool(name="student_record_lookup", title="Student Record Lookup", description="Looks up student information based on their student ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def student_record_lookup(student_id: str):
    s = _crc(student_id)
    return json.dumps({"student_id": student_id, "name": _pick(_NAMES,s),
        "major": _pick(_MAJORS,s), "year": s%4+1, "gpa": round(2.0+s%20*0.1,2),
        "total_credits": 60+s%70, "status": _pick(["ENROLLED","ON_LEAVE","GRADUATED"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="course_lookup", title="Course Lookup", description="Looks up course information based on the course code.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def course_lookup(course_code: str):
    s = _crc(course_code)
    return json.dumps({"course_code": course_code, "name": _pick(["Data Structures","Microeconomics","Circuit Theory","Developmental Psychology","Organic Chemistry"],s),
        "credits": 3, "instructor": f"Prof. {_pick(_NAMES,s+1)}",
        "capacity": 40, "enrolled": 30+s%10, "prerequisite": _pick(["None","Introduction to Programming","Principles of Economics"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="enrollment_status", title="Enrollment Status Lookup", description="Looks up the current semester's enrollment status based on the student ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def enrollment_status(student_id: str):
    s = _crc(student_id+"enr")
    return json.dumps({"student_id": student_id, "semester": "2026-1",
        "enrolled_credits": 15+s%6, "max_credits": 21,
        "courses": [{"code": f"CS{100+s%400}", "name": "Data Structures", "credits": 3},
                    {"code": f"BA{100+(s+1)%400}", "name": "Principles of Marketing", "credits": 3}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="grade_lookup", title="Grade Lookup", description="Looks up grades based on the student ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def grade_lookup(student_id: str, semester: str = "2025-2"):
    s = _crc(student_id+semester)
    return json.dumps({"student_id": student_id, "semester": semester,
        "grades": [{"course": "Algorithms", "grade": _pick(["A+","A0","B+","B0","C+"],s), "credits": 3},
                   {"course": "Business Strategy", "grade": _pick(["A+","A0","B+","B0"],s+1), "credits": 3}],
        "semester_gpa": round(3.0+s%10*0.1,2)}, ensure_ascii=False, indent=2)

@mcp.tool(name="scholarship_lookup", title="Scholarship Lookup", description="Looks up scholarship award status based on the student ID.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def scholarship_lookup(student_id: str):
    s = _crc(student_id+"sch")
    return json.dumps({"student_id": student_id,
        "current_scholarship": _pick(["Merit Scholarship (50%)","Merit Scholarship (100%)","None","National Scholarship"],s),
        "gpa_requirement": 3.0, "min_credits": 15}, ensure_ascii=False, indent=2)

@mcp.tool(name="enroll_course", title="Enroll in Course", description="Enrolls a student in a course.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def enroll_course(student_id: str, course_code: str):
    return json.dumps({"student_id": student_id, "course_code": course_code,
        "status": "ENROLLED", "enrolled_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="drop_course", title="Drop Course", description="Drops a course a student is currently enrolled in.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def drop_course(student_id: str, course_code: str, reason: str):
    return json.dumps({"student_id": student_id, "course_code": course_code,
        "status": "DROPPED", "grade_record": "W", "reason": reason, "dropped_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="submit_grade_appeal", title="Submit Grade Appeal", description="Submits an appeal regarding a grade.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def submit_grade_appeal(student_id: str, course_code: str, reason: str):
    return json.dumps({"appeal_id": _rid("APL"), "student_id": student_id,
        "course_code": course_code, "status": "SUBMITTED", "reason": reason,
        "submitted_at": _now(), "review_deadline": "Within 7 days of submission"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_academic_note", title="Create Academic Note", description="Records details of an academic process.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_academic_note(entity_id: str, note: str, entity_type: str = "student", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("AN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
