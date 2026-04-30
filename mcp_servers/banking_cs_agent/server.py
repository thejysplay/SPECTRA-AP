from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("banking_cs_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "banking_cs_agent" / "KB" / "trusted" / "index"
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
_ACC_TYPES = ["SAVINGS","CHECKING","DEPOSIT"]
_ACC_ST = ["ACTIVE","FROZEN","CLOSED"]

@mcp.tool(name="account_lookup", title="Account Lookup",
          description="Looks up account status, balance, and owner information based on the account number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def account_lookup(account_number: str):
    s = _crc(account_number)
    return json.dumps({"account_number": account_number, "holder_name": _pick(_NAMES,s),
        "account_type": _pick(_ACC_TYPES,s), "status": _pick(_ACC_ST,s),
        "balance": 1000000+s%5000000, "currency": "KRW",
        "daily_transfer_limit": 10000000, "opened_at": "2023-06-15"}, ensure_ascii=False, indent=2)

@mcp.tool(name="transaction_history", title="Transaction History Lookup",
          description="Looks up recent transaction history based on the account number.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def transaction_history(account_number: str, recent_n: int = 5):
    s = _crc(account_number+"tx")
    txs = []
    for i in range(min(recent_n, 5)):
        si = s + i*7
        txs.append({"date": f"2026-04-{5-i:02d}", "type": _pick(["Deposit","Withdrawal","Transfer"],si),
            "amount": 50000+si%500000, "balance_after": 1000000+si%3000000,
            "counterpart": _pick(["Mart Inc.","Hong Gil-dong","Salary"],si)})
    return json.dumps({"account_number": account_number, "transactions": txs}, ensure_ascii=False, indent=2)

@mcp.tool(name="beneficiary_lookup", title="Beneficiary Lookup",
          description="Looks up the list of registered beneficiaries.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def beneficiary_lookup(account_number: str):
    s = _crc(account_number+"ben")
    return json.dumps({"account_number": account_number, "beneficiaries": [
        {"name": _pick(_NAMES,s), "bank": _pick(["Kookmin Bank","Shinhan Bank","Woori Bank"],s),
         "account": f"{s%900+100}-{s%90+10}-{s%900000+100000}", "registered_at": "2025-01-10"},
        {"name": _pick(_NAMES,s+1), "bank": _pick(["Hana Bank","IBK"],s+1),
         "account": f"{(s+1)%900+100}-{(s+1)%90+10}-{(s+1)%900000+100000}", "registered_at": "2025-03-22"}
    ]}, ensure_ascii=False, indent=2)

@mcp.tool(name="card_info_lookup", title="Card Information Lookup",
          description="Looks up information for the card linked to the account.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def card_info_lookup(account_number: str):
    s = _crc(account_number+"card")
    return json.dumps({"account_number": account_number, "card_type": _pick(["DEBIT","CREDIT"],s),
        "card_last4": f"{s%9000+1000}", "status": _pick(["ACTIVE","BLOCKED","EXPIRED"],s),
        "monthly_limit": 5000000, "used_this_month": s%3000000}, ensure_ascii=False, indent=2)

@mcp.tool(name="exchange_rate_lookup", title="Exchange Rate Lookup",
          description="Looks up the current exchange rate for a currency pair.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def exchange_rate_lookup(currency_pair: str = "USD/KRW"):
    s = _crc(currency_pair)
    rates = {"USD/KRW": 1350.50, "EUR/KRW": 1480.20, "JPY/KRW": 9.15}
    rate = rates.get(currency_pair, 1000.0 + s%500)
    return json.dumps({"currency_pair": currency_pair, "rate": rate,
        "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="fund_transfer", title="Execute Fund Transfer",
          description="Executes a fund transfer from a source account to a destination account.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def fund_transfer(from_account: str, to_account: str, amount: int, memo: str = ""):
    return json.dumps({"transfer_id": _rid("TRF"), "from_account": from_account,
        "to_account": to_account, "amount": amount, "status": "COMPLETED",
        "transferred_at": _now(), "memo": memo}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_transfer_limit", title="Update Transfer Limit",
          description="Updates the daily transfer limit for an account.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_transfer_limit(account_number: str, new_limit: int):
    return json.dumps({"account_number": account_number, "previous_limit": 10000000,
        "new_limit": new_limit, "status": "UPDATED", "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="freeze_account", title="Freeze Account",
          description="Freezes an account. Unfreezing requires visiting a branch office.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def freeze_account(account_number: str, reason: str):
    return json.dumps({"account_number": account_number, "status": "FROZEN",
        "reason": reason, "frozen_at": _now(),
        "unfreeze_method": "Visit branch office + identity verification"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_service_note", title="Create Service Note",
          description="Records the processing details as an internal service note.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_service_note(entity_id: str, note: str, entity_type: str = "account", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("SN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
