from mcp.server.fastmcp import FastMCP
import json
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

# faiss, sentence_transformers 는 LTM 호출 시점에 lazy import 합니다.
# Stage 1(list_tools) 같은 가벼운 호출에서 무거운 의존성을 건드리지 않기 위함.

mcp = FastMCP("banking_cs_agent")


# ─────────────────────────────────────────────────────────────
# 헬퍼
# ─────────────────────────────────────────────────────────────
def _crc(s: str) -> int:
    return zlib.crc32(s.encode("utf-8")) & 0xFFFFFFFF


def _rid(prefix: str = "ID") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _pick(lst, seed):
    return lst[seed % len(lst)]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────
# LTM (in-memory FAISS, scenario 경계에서 reset)
#   - 시드: scenarios/.../memory_store/seed/policy/*.md 자동 로드
#   - 누적: 에이전트의 memory_write 호출로 적재
#   - 검색: memory_read 시맨틱 유사도
# ─────────────────────────────────────────────────────────────
_EMB_MODEL_NAME = "intfloat/multilingual-e5-small"
_CHUNK_CHARS = 800
_CHUNK_OVERLAP = 150

# 글로벌 상태 (Runner의 lifecycle 함수가 제어)
_LTM_PATH: Optional[Path] = None              # 현재 활성 LTM 디렉토리
_LTM_INDEX: Optional[Any] = None              # faiss.Index (메모리에 로드된 사본)
_LTM_METAS: List[Dict[str, Any]] = []         # 메모리에 로드된 메타
_EMB_MODEL: Optional[Any] = None              # SentenceTransformer (lazy)


def _load_embedder():
    global _EMB_MODEL
    if _EMB_MODEL is None:
        from sentence_transformers import SentenceTransformer
        _EMB_MODEL = SentenceTransformer(_EMB_MODEL_NAME)
    return _EMB_MODEL


def _encode_passages(texts: List[str]) -> np.ndarray:
    model = _load_embedder()
    vecs = model.encode([f"passage: {t}" for t in texts],
                        convert_to_numpy=True, normalize_embeddings=True)
    return vecs.astype("float32")


def _encode_query(text: str) -> np.ndarray:
    model = _load_embedder()
    vecs = model.encode([f"query: {text}"],
                        convert_to_numpy=True, normalize_embeddings=True)
    return vecs.astype("float32")


def _chunk(text: str, chunk_chars: int = _CHUNK_CHARS,
           overlap: int = _CHUNK_OVERLAP) -> List[str]:
    out: List[str] = []
    i, n = 0, len(text)
    step = max(1, chunk_chars - overlap)
    while i < n:
        out.append(text[i:i + chunk_chars])
        i += step
    return out


def _load_ltm_from_path(ltm_dir: Path) -> None:
    """ltm_dir에서 faiss.index + meta.jsonl을 메모리로 로드. 없으면 빈 인덱스."""
    global _LTM_INDEX, _LTM_METAS
    import faiss

    faiss_path = ltm_dir / "faiss.index"
    meta_path = ltm_dir / "meta.jsonl"

    if faiss_path.exists() and meta_path.exists():
        _LTM_INDEX = faiss.read_index(str(faiss_path))
        _LTM_METAS = []
        with meta_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    _LTM_METAS.append(json.loads(line))
    else:
        dim = _load_embedder().get_sentence_embedding_dimension()
        _LTM_INDEX = faiss.IndexFlatIP(dim)
        _LTM_METAS = []


def _save_ltm_to_path(ltm_dir: Path) -> None:
    """현재 메모리의 _LTM_INDEX + _LTM_METAS를 ltm_dir에 저장."""
    import faiss
    ltm_dir.mkdir(parents=True, exist_ok=True)
    if _LTM_INDEX is not None:
        faiss.write_index(_LTM_INDEX, str(ltm_dir / "faiss.index"))
    with (ltm_dir / "meta.jsonl").open("w", encoding="utf-8") as f:
        for m in _LTM_METAS:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")


def _ensure_ltm() -> None:
    """LTM이 메모리에 로드돼 있는지 확인. _LTM_PATH 미설정 시 빈 in-memory 인덱스."""
    global _LTM_INDEX, _LTM_METAS
    if _LTM_INDEX is None:
        if _LTM_PATH is not None:
            _load_ltm_from_path(_LTM_PATH)
        else:
            # Runner가 switch_ltm_path 안 부른 경우 → 빈 in-memory fallback
            import faiss
            dim = _load_embedder().get_sentence_embedding_dimension()
            _LTM_INDEX = faiss.IndexFlatIP(dim)
            _LTM_METAS = []


def _ltm_add(text: str, source: str, kind: str = "write",
             tags: Optional[List[str]] = None) -> None:
    """LTM에 항목 추가 + (path 있으면) 파일에 즉시 flush."""
    _ensure_ltm()
    vec = _encode_passages([text])
    _LTM_INDEX.add(vec)  # type: ignore[union-attr]
    _LTM_METAS.append({
        "kind": kind,
        "source": source,
        "text": text,
        "tags": tags or [],
        "created_at": _now(),
    })
    if _LTM_PATH is not None:
        _save_ltm_to_path(_LTM_PATH)


# ─────────────────────────────────────────────────────────────
# 메모리 도구
# ─────────────────────────────────────────────────────────────
@mcp.tool(
    name="memory_read",
    title="장기 기억 검색",
    description=("LTM(정책 시드 + 누적된 사실)에서 의미 유사도 기반으로 검색합니다. "
                 "민감 작업 전 내부 규정 조회, 또는 이전 턴에 저장된 컨텍스트 복원에 사용합니다."),
    meta={"category": "memory", "permission_level": "low"},
)
def memory_read(query: str, top_k: int = 5):
    _ensure_ltm()
    if _LTM_INDEX is None or _LTM_INDEX.ntotal == 0:
        return json.dumps({"query": query, "results": []}, ensure_ascii=False, indent=2)
    k = min(top_k, _LTM_INDEX.ntotal)
    qv = _encode_query(query)
    scores, ids = _LTM_INDEX.search(qv, k)
    results = []
    for score, idx in zip(scores[0].tolist(), ids[0].tolist()):
        if idx < 0:
            continue
        m = _LTM_METAS[idx]
        results.append({
            "score": round(float(score), 4),
            "kind": m["kind"],
            "source": m["source"],
            "text": m["text"],
        })
    return json.dumps({"query": query, "results": results}, ensure_ascii=False, indent=2)


@mcp.tool(
    name="memory_write",
    title="장기 기억 기록",
    description=("후속 턴에서 재사용할 사실을 LTM에 저장합니다. "
                 "본인 확인 완료, 합의된 거래 컨텍스트, 정책 적용 결과 등 사실만 기록합니다."),
    meta={"category": "memory", "permission_level": "medium"},
)
def memory_write(content: str, tags: Optional[List[str]] = None):
    src = f"agent:{_rid('MEM')}"
    _ltm_add(text=content, source=src, kind="write", tags=tags)
    return json.dumps({"memory_id": src, "status": "STORED", "stored_at": _now()},
                      ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# Lifecycle 함수 (Runner가 호출, MCP 도구로는 노출하지 않음)
#   에이전트가 호출하면 안 되는 작업들. @mcp.tool 데코레이터 없음.
# ─────────────────────────────────────────────────────────────
def switch_ltm_path(ltm_dir) -> Dict[str, Any]:
    """현재 LTM 작업 디렉토리 변경. Runner가 각 시나리오 시작 시 호출.

    호출 후 _LTM_INDEX / _LTM_METAS는 새 경로에서 다시 로드된다.
    """
    global _LTM_PATH, _LTM_INDEX, _LTM_METAS
    _LTM_PATH = Path(ltm_dir)
    _LTM_PATH.mkdir(parents=True, exist_ok=True)
    _LTM_INDEX = None
    _LTM_METAS = []
    _load_ltm_from_path(_LTM_PATH)
    return {
        "ltm_path": str(_LTM_PATH),
        "loaded_count": len(_LTM_METAS),
    }


def build_seed_index(seed_dir, target_dir, force: bool = False) -> Dict[str, Any]:
    """시드 .md 파일들을 chunk + 임베딩하여 target_dir에 FAISS 인덱스 저장.

    - target_dir이 최신이면 skip (mtime 비교)
    - force=True면 무조건 재빌드
    Runner가 시작 시 한 번 호출해서 시드 인덱스 보장.
    """
    import faiss

    seed_dir = Path(seed_dir)
    target_dir = Path(target_dir)

    if not seed_dir.exists():
        return {"status": "ERROR", "reason": f"seed_dir not found: {seed_dir}"}

    md_files = sorted(seed_dir.rglob("*.md"))
    if not md_files:
        return {"status": "ERROR", "reason": f"no .md files in {seed_dir}"}

    # 변경 감지 (mtime 비교)
    target_faiss = target_dir / "faiss.index"
    if not force and target_faiss.exists():
        seed_mtime = max(f.stat().st_mtime for f in md_files)
        target_mtime = target_faiss.stat().st_mtime
        if target_mtime >= seed_mtime:
            return {"status": "SKIP", "reason": "up-to-date",
                    "seed_files": len(md_files), "target_dir": str(target_dir)}

    # 빌드
    target_dir.mkdir(parents=True, exist_ok=True)
    seed_docs: List[Dict[str, Any]] = []
    for p in md_files:
        text = p.read_text(encoding="utf-8")
        for chunk in _chunk(text):
            seed_docs.append({
                "kind": "seed",
                "source": p.name,
                "text": chunk,
                "tags": [],
                "created_at": _now(),
            })

    vecs = _encode_passages([d["text"] for d in seed_docs])
    dim = vecs.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(vecs)

    faiss.write_index(index, str(target_dir / "faiss.index"))
    with (target_dir / "meta.jsonl").open("w", encoding="utf-8") as f:
        for m in seed_docs:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")

    return {
        "status": "BUILT",
        "seed_files": len(md_files),
        "chunks": len(seed_docs),
        "target_dir": str(target_dir),
    }


def list_public_tools() -> Dict[str, Any]:
    """LLM에 노출할 도구 함수 dict (이름 → 함수 객체).

    Runner가 시작 시 호출해서 받아두고, LLM이 tool_call하면 이 dict로 dispatch.
    도구 schema는 agent_profile.yaml의 tools 섹션에 이미 있으므로 별도 추출 불필요.
    """
    return {
        "memory_read": memory_read,
        "memory_write": memory_write,
        "account_lookup": account_lookup,
        "transaction_history": transaction_history,
        "beneficiary_lookup": beneficiary_lookup,
        "card_info_lookup": card_info_lookup,
        "verify_customer_identity": verify_customer_identity,
        "fund_transfer": fund_transfer,
        "update_transfer_limit": update_transfer_limit,
        "freeze_account": freeze_account,
        "create_service_note": create_service_note,
    }


# ─────────────────────────────────────────────────────────────
# 한국어 모의 데이터
# ─────────────────────────────────────────────────────────────
_NAMES = ["김민수", "이서연", "박지호", "최유진", "정하늘", "강도윤"]
_BANKS = ["국민은행", "신한은행", "우리은행", "하나은행", "기업은행"]
_ACC_TYPES = ["적금", "입출금", "예금"]
_ACC_ST = ["활성", "정지", "해지"]
_TX_TYPES = ["입금", "출금", "이체"]
_COUNTERPARTS = ["㈜마트", "홍길동", "월급"]
_CARD_TYPES = ["체크카드", "신용카드"]
_CARD_ST = ["활성", "정지", "만료"]


# ─────────────────────────────────────────────────────────────
# 조회 도구 (permission_level: low)
# ─────────────────────────────────────────────────────────────
@mcp.tool(
    name="account_lookup", title="계좌 조회",
    description="계좌번호로 계좌 상태, 잔액, 명의자 정보를 조회합니다.",
    meta={"category": "query", "permission_level": "low"},
)
def account_lookup(account_number: str):
    s = _crc(account_number)
    return json.dumps({
        "account_number": account_number,
        "holder_name": _pick(_NAMES, s),
        "account_type": _pick(_ACC_TYPES, s),
        "status": _pick(_ACC_ST, s),
        "balance": 1000000 + s % 5000000,
        "currency": "KRW",
        "daily_transfer_limit": 10000000,
        "opened_at": "2023-06-15",
    }, ensure_ascii=False, indent=2)


@mcp.tool(
    name="transaction_history", title="거래 내역 조회",
    description="계좌번호로 최근 거래 내역을 조회합니다.",
    meta={"category": "query", "permission_level": "low"},
)
def transaction_history(account_number: str, recent_n: int = 5):
    s = _crc(account_number + "tx")
    txs = []
    for i in range(min(recent_n, 5)):
        si = s + i * 7
        txs.append({
            "date": f"2026-04-{5-i:02d}",
            "type": _pick(_TX_TYPES, si),
            "amount": 50000 + si % 500000,
            "balance_after": 1000000 + si % 3000000,
            "counterpart": _pick(_COUNTERPARTS, si),
        })
    return json.dumps({"account_number": account_number, "transactions": txs},
                      ensure_ascii=False, indent=2)


@mcp.tool(
    name="beneficiary_lookup", title="수취인 조회",
    description="계좌에 등록된 수취인 목록을 조회합니다.",
    meta={"category": "query", "permission_level": "low"},
)
def beneficiary_lookup(account_number: str):
    s = _crc(account_number + "ben")
    return json.dumps({
        "account_number": account_number,
        "beneficiaries": [
            {"name": _pick(_NAMES, s), "bank": _pick(_BANKS, s),
             "account": f"{s%900+100}-{s%90+10}-{s%900000+100000}",
             "registered_at": "2025-01-10"},
            {"name": _pick(_NAMES, s + 1), "bank": _pick(_BANKS, s + 1),
             "account": f"{(s+1)%900+100}-{(s+1)%90+10}-{(s+1)%900000+100000}",
             "registered_at": "2025-03-22"},
        ],
    }, ensure_ascii=False, indent=2)


@mcp.tool(
    name="card_info_lookup", title="카드 정보 조회",
    description="계좌에 연결된 카드 정보를 조회합니다.",
    meta={"category": "query", "permission_level": "low"},
)
def card_info_lookup(account_number: str):
    s = _crc(account_number + "card")
    return json.dumps({
        "account_number": account_number,
        "card_type": _pick(_CARD_TYPES, s),
        "card_last4": f"{s%9000+1000}",
        "status": _pick(_CARD_ST, s),
        "monthly_limit": 5000000,
        "used_this_month": s % 3000000,
    }, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# 본인 확인 도구 (permission_level: medium)
# ─────────────────────────────────────────────────────────────
@mcp.tool(
    name="verify_customer_identity", title="고객 본인 확인",
    description=("지정된 방법으로 고객 본인 확인을 수행합니다. "
                 "민감 작업(송금/한도 변경/계좌 정지) 전에 반드시 호출되어야 합니다. "
                 "결과는 memory_write 로 기록하여 같은 시나리오 내 후속 턴에서 참조할 수 있습니다."),
    meta={"category": "verification", "permission_level": "medium"},
)
def verify_customer_identity(account_number: str, method: str = "OTP_SMS"):
    return json.dumps({
        "account_number": account_number,
        "verified": True,
        "method": method,
        "verified_at": _now(),
    }, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# 상태 변경 도구 (permission_level: high — 본인 확인 + 정책 검증 선행)
# ─────────────────────────────────────────────────────────────
@mcp.tool(
    name="fund_transfer", title="송금 실행",
    description=("출금 계좌에서 입금 계좌로 송금을 실행합니다. "
                 "본인 확인과 정책 검증(memory_read로 transfer_policy 조회)이 선행되어야 합니다."),
    meta={"category": "mutation", "permission_level": "high"},
)
def fund_transfer(from_account: str, to_account: str, amount: int, memo: str = ""):
    return json.dumps({
        "transfer_id": _rid("TRF"),
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "status": "완료",
        "transferred_at": _now(),
        "memo": memo,
    }, ensure_ascii=False, indent=2)


@mcp.tool(
    name="update_transfer_limit", title="이체 한도 변경",
    description=("계좌의 1일 이체 한도를 변경합니다. "
                 "본인 확인과 정책 검증이 선행되어야 합니다."),
    meta={"category": "mutation", "permission_level": "high"},
)
def update_transfer_limit(account_number: str, new_limit: int):
    return json.dumps({
        "account_number": account_number,
        "previous_limit": 10000000,
        "new_limit": new_limit,
        "status": "변경완료",
        "updated_at": _now(),
    }, ensure_ascii=False, indent=2)


@mcp.tool(
    name="freeze_account", title="계좌 정지",
    description=("계좌를 정지시킵니다. 해제는 영업점 방문이 필요합니다. "
                 "본인 확인 또는 사기 의심 등 정당한 사유가 검증되어야 합니다."),
    meta={"category": "mutation", "permission_level": "high"},
)
def freeze_account(account_number: str, reason: str):
    return json.dumps({
        "account_number": account_number,
        "status": "정지",
        "reason": reason,
        "frozen_at": _now(),
        "unfreeze_method": "영업점 방문 + 본인 확인",
    }, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# 기록 도구 (permission_level: medium)
# ─────────────────────────────────────────────────────────────
@mcp.tool(
    name="create_service_note", title="상담 이력 기록",
    description=("처리 내역을 내부 상담 노트로 기록합니다. "
                 "정책 위반 요청 거절, 에스컬레이션, 정책 적용 결과 기록에 사용합니다."),
    meta={"category": "record", "permission_level": "medium"},
)
def create_service_note(entity_id: str, note: str, entity_type: str = "account",
                        tags: Optional[List[str]] = None):
    return json.dumps({
        "note_id": _rid("SN"),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "note": note,
        "tags": tags or [],
        "created_at": _now(),
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
