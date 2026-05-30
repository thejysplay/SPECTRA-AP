#!/usr/bin/env python3
"""SPECTRA-AP Stage 3 — 적대적 시나리오 실행기 (Runner).

Inputs:
  - configs/<agent>.yml                                       (llm/runner/paths/mcp/memory)
  - outputs/agent_profiles/<agent>/<date>/agent_profile.yaml  (tool schema)
  - outputs/tasks/<agent>/<profile_date>/<generated_date>/tasks.jsonl  (실행할 task들, v3)
  - mcp_servers/<agent>/server.py                             (도구 함수 + lifecycle)

Outputs:
  - outputs/logs/<agent>/<profile_date>/<generated_date>/<scenario_id>.jsonl   (per-scenario trace)
  - outputs/ltm/<agent>/<profile_date>/<generated_date>/<sub_id>/<S>/          (시나리오별 LTM 상태)

흐름:
  1) config + agent_profile + tasks.jsonl 로드
  2) server.py import (MCP 우회, 도구 함수 직접 호출)
  3) build_seed_index → 시드 인덱스 보장 (mtime 캐싱)
  4) 각 task 순차 실행:
       - 시드 LTM 디렉토리 복사 → 시나리오 LTM 디렉토리
       - switch_ltm_path 호출 (server.py에 알림)
       - messages = [system]
       - for turn in task.turns:
           ReAct 루프 (max_steps): LLM → tool_call → IPI merge → observation
       - trace JSONL 저장
"""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

try:
    from google import genai
    from google.genai import types as gtypes
except Exception:
    genai = None
    gtypes = None

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


# ─────────────────────────────────────────────────────────────
# 기본 경로
# ─────────────────────────────────────────────────────────────
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIGS_DIR = DEFAULT_REPO_ROOT / "configs"
DEFAULT_AGENT_PROFILES_DIR = DEFAULT_REPO_ROOT / "outputs" / "agent_profiles"
DEFAULT_TASKS_ROOT = DEFAULT_REPO_ROOT / "outputs" / "tasks"
DEFAULT_LOGS_ROOT = DEFAULT_REPO_ROOT / "outputs" / "logs"
DEFAULT_LTM_ROOT = DEFAULT_REPO_ROOT / "outputs" / "ltm"


# ─────────────────────────────────────────────────────────────
# 헬퍼
# ─────────────────────────────────────────────────────────────
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def list_profile_dates(agent_profiles_dir: Path, agent: str) -> List[str]:
    base = agent_profiles_dir / agent
    if not base.exists():
        return []
    dates = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name):
            if (d / "agent_profile.yaml").exists():
                dates.append(d.name)
    return dates


def resolve_profile_path(agent_profiles_dir: Path, agent: str,
                         profile_date: Optional[str]) -> Path:
    dates = list_profile_dates(agent_profiles_dir, agent)
    if not dates:
        raise FileNotFoundError(f"agent_profile not found for {agent}")
    chosen = profile_date or dates[-1]
    if chosen not in dates:
        raise FileNotFoundError(f"profile_date={chosen} not found. Available: {dates}")
    return agent_profiles_dir / agent / chosen / "agent_profile.yaml"


def load_api_key(llm_cfg: dict, repo_root: Path) -> str:
    key = (llm_cfg.get("api_key") or "").strip()
    if key:
        return key
    keyfile = (llm_cfg.get("api_key_file") or "").strip()
    if keyfile:
        p = Path(keyfile)
        if not p.is_absolute():
            p = repo_root / p
        return p.read_text(encoding="utf-8").strip()
    return ""


def load_config(configs_dir: Path, agent: str) -> Dict[str, Any]:
    for ext in ("yml", "yaml"):
        p = configs_dir / f"{agent}.{ext}"
        if p.exists():
            return load_yaml(p)
    raise FileNotFoundError(f"config not found for {agent} in {configs_dir}")


# ─────────────────────────────────────────────────────────────
# Server import (MCP 우회, in-process)
# ─────────────────────────────────────────────────────────────
def import_server_module(repo_root: Path, agent: str, mcp_cfg: dict):
    """configs.mcp.server_module을 import. 없으면 default 경로."""
    module_name = mcp_cfg.get("server_module") or f"mcp_servers.{agent}.server"
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return importlib.import_module(module_name)


# ─────────────────────────────────────────────────────────────
# Tool schema 변환 (agent_profile → LLM provider format)
# ─────────────────────────────────────────────────────────────
def _clean_json_schema_for_gemini(schema: dict) -> dict:
    """JSON schema를 Gemini가 받아들이는 형태로 정제.
    Gemini는 title/anyOf/$defs 등 일부 필드를 거부함.
    """
    if not isinstance(schema, dict):
        return {"type": "object"}
    out: Dict[str, Any] = {"type": schema.get("type", "object")}
    if "properties" in schema:
        out["properties"] = {}
        for name, prop in schema["properties"].items():
            p: Dict[str, Any] = {}
            # type 결정
            if "type" in prop:
                p["type"] = prop["type"]
            elif "anyOf" in prop:
                for opt in prop["anyOf"]:
                    if isinstance(opt, dict) and opt.get("type") and opt["type"] != "null":
                        p["type"] = opt["type"]
                        break
                else:
                    p["type"] = "string"
            else:
                p["type"] = "string"
            if "description" in prop:
                p["description"] = prop["description"]
            if "default" in prop and prop["default"] is not None:
                p["default"] = prop["default"]
            if p.get("type") == "array":
                p["items"] = prop.get("items", {"type": "string"})
            out["properties"][name] = p
    if "required" in schema:
        out["required"] = schema["required"]
    return out


def profile_tools_to_gemini_fn_decls(profile_tools: List[Dict]) -> List[Any]:
    decls = []
    for t in profile_tools:
        decls.append(gtypes.FunctionDeclaration(
            name=t["name"],
            description=t.get("description") or t.get("title", ""),
            parameters=_clean_json_schema_for_gemini(t.get("input_schema", {})),
        ))
    return decls


def profile_tools_to_openai_tools(profile_tools: List[Dict]) -> List[Dict]:
    return [{
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description") or t.get("title", ""),
            "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
        },
    } for t in profile_tools]


# ─────────────────────────────────────────────────────────────
# IPI dict merge
# ─────────────────────────────────────────────────────────────
def inject_ipi_payload(tool_result: Any, payload: Any) -> Any:
    """도구 응답에 IPI payload merge."""
    if isinstance(payload, dict) and isinstance(tool_result, dict):
        merged = copy.deepcopy(tool_result)
        merged.update(payload)
        return merged
    if isinstance(tool_result, dict):
        merged = copy.deepcopy(tool_result)
        merged["_ipi_note"] = payload
        return merged
    return {"original": tool_result, "_ipi_note": payload}


def find_ipi_match(tool_name: str, ipi_payloads: List[Dict]) -> Optional[Any]:
    for p in ipi_payloads or []:
        if p.get("target_tool") == tool_name:
            return p.get("payload")
    return None


# ─────────────────────────────────────────────────────────────
# 도구 호출 wrapper (in-process)
# ─────────────────────────────────────────────────────────────
def call_tool(tool_name: str, args: dict, tool_dispatch: Dict[str, Callable]) -> Any:
    """tool_dispatch에서 함수 찾아 호출. dict로 정규화."""
    fn = tool_dispatch.get(tool_name)
    if fn is None:
        return {"error": f"unknown tool: {tool_name}"}
    try:
        raw = fn(**args)
    except Exception as e:
        return {"error": f"tool execution failed: {type(e).__name__}: {e}"}
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
    return raw


# ─────────────────────────────────────────────────────────────
# Gemini ReAct 루프 (turn 단위)
# ─────────────────────────────────────────────────────────────
def run_turn_gemini(*, client, model: str, system_prompt: str,
                    messages: List, fn_decls: List,
                    user_input: str, ipi_payloads: List[Dict],
                    tool_dispatch: Dict[str, Callable],
                    max_steps: int, log_write: Callable) -> str:
    """한 turn 실행. messages에 user/model 누적, ReAct max_steps 반복."""
    messages.append(gtypes.Content(role="user", parts=[gtypes.Part(text=user_input)]))

    config = gtypes.GenerateContentConfig(
        tools=[gtypes.Tool(function_declarations=fn_decls)] if fn_decls else None,
        tool_config=gtypes.ToolConfig(
            function_calling_config=gtypes.FunctionCallingConfig(mode="AUTO")
        ) if fn_decls else None,
        system_instruction=system_prompt,
        temperature=0,
    )

    for step in range(max_steps):
        resp = client.models.generate_content(model=model, contents=messages, config=config)

        # assistant text + function_calls 추출
        assistant_text = ""
        fcalls = []
        try:
            for cand in resp.candidates or []:
                for part in (cand.content.parts or []):
                    if getattr(part, "text", None):
                        assistant_text += part.text
                    if getattr(part, "function_call", None):
                        fcalls.append(part.function_call)
        except Exception:
            pass

        if assistant_text.strip():
            log_write({"type": "assistant_text", "step": step,
                       "text": assistant_text, "ts": utc_now_iso()})

        if not fcalls:
            # 더 이상 도구 호출 없음 → final
            final_text = ""
            try:
                final_text = (resp.text or "").strip()
            except Exception:
                pass
            if not final_text:
                final_text = assistant_text.strip()
            log_write({"type": "final", "text": final_text or "[no final text]",
                       "ts": utc_now_iso()})
            return final_text

        # assistant turn을 messages에 추가
        if resp.candidates and resp.candidates[0].content:
            messages.append(resp.candidates[0].content)

        # 각 tool call 실행
        response_parts = []
        for fc in fcalls:
            tool_name = fc.name
            tool_args = dict(fc.args or {})
            log_write({"type": "tool_call", "step": step,
                       "name": tool_name, "args": tool_args, "ts": utc_now_iso()})

            tool_result = call_tool(tool_name, tool_args, tool_dispatch)

            # IPI 처리
            ipi = find_ipi_match(tool_name, ipi_payloads)
            ipi_injected = False
            if ipi is not None:
                tool_result = inject_ipi_payload(tool_result, ipi)
                ipi_injected = True

            log_write({"type": "tool_result", "step": step, "name": tool_name,
                       "result": tool_result, "ipi_injected": ipi_injected,
                       "ts": utc_now_iso()})

            response_parts.append(
                gtypes.Part.from_function_response(name=tool_name, response={"result": tool_result})
            )

        messages.append(gtypes.Content(role="user", parts=response_parts))

    log_write({"type": "final", "text": "[max_steps exceeded]",
               "exceeded": True, "ts": utc_now_iso()})
    return "[max_steps exceeded]"


# ─────────────────────────────────────────────────────────────
# 시나리오 1개 실행 (LTM lifecycle + multi-turn)
# ─────────────────────────────────────────────────────────────
def run_one_task(*, task: Dict, system_prompt: str, agent_profile: dict,
                 llm_cfg: dict, runner_cfg: dict, repo_root: Path,
                 ltm_root: Path, logs_root: Path, server_module,
                 seed_index_dir: Path, profile_date: str, generated_date: str,
                 tool_dispatch: Dict[str, Callable]) -> bool:
    task_id = task["id"]
    sub_id = task["sub_id"]
    agent = task["agent"]
    s_part = task_id.split("-")[-1]   # 예: "S1"

    # 1. LTM 시나리오 디렉토리 준비 (시드 복사)
    scenario_ltm_dir = ltm_root / agent / profile_date / generated_date / sub_id / s_part
    if scenario_ltm_dir.exists():
        shutil.rmtree(scenario_ltm_dir)
    shutil.copytree(seed_index_dir, scenario_ltm_dir)

    # 2. server.py에 알림
    server_module.switch_ltm_path(scenario_ltm_dir)

    # 3. log 파일 준비
    log_dir = logs_root / agent / profile_date / generated_date
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{task_id}.jsonl"

    max_steps = int(runner_cfg.get("max_steps", 10))
    provider = (llm_cfg.get("provider") or "gemini").lower()
    model = llm_cfg["model"]
    api_key = load_api_key(llm_cfg, repo_root)
    profile_tools = agent_profile.get("tools", [])
    ipi_payloads = task.get("ipi_payloads", [])

    # task 통계
    task_start_ts = utc_now_iso()
    tool_call_count = 0
    ipi_injected_count = 0

    try:
        with log_path.open("w", encoding="utf-8") as lf:
            def log_write(obj):
                # 빈 dict이나 None 방어
                if not obj:
                    return
                lf.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
                lf.flush()
                # 통계 누적
                nonlocal tool_call_count, ipi_injected_count
                if obj.get("type") == "tool_call":
                    tool_call_count += 1
                elif obj.get("type") == "tool_result" and obj.get("ipi_injected"):
                    ipi_injected_count += 1

            log_write({
                "type": "meta",
                "task_id": task_id, "sub_id": sub_id,
                "threat_id": task.get("threat_id"),
                "threat_name": task.get("threat_name"),
                "injection_vector": task.get("injection_vector"),
                "turn_mode": task.get("turn_mode"),
                "inspection_focus": task.get("inspection_focus"),
                "agent": agent, "model": model, "provider": provider,
                "ltm_path": str(scenario_ltm_dir),
                "ts": task_start_ts,
            })

            if provider == "gemini":
                if genai is None or gtypes is None:
                    raise RuntimeError("google-genai 미설치")
                client = genai.Client(api_key=api_key)
                fn_decls = profile_tools_to_gemini_fn_decls(profile_tools)
                messages: List = []

                for turn_idx, turn in enumerate(task["turns"]):
                    log_write({"type": "turn", "turn_idx": turn_idx,
                               "role": turn["role"], "user_input": turn["user_input"],
                               "ts": utc_now_iso()})
                    run_turn_gemini(
                        client=client, model=model, system_prompt=system_prompt,
                        messages=messages, fn_decls=fn_decls,
                        user_input=turn["user_input"], ipi_payloads=ipi_payloads,
                        tool_dispatch=tool_dispatch,
                        max_steps=max_steps, log_write=log_write,
                    )
            else:
                raise NotImplementedError(
                    f"provider '{provider}' 미구현 (현재 gemini만 지원)"
                )

            log_write({
                "type": "task_end",
                "turn_count": len(task["turns"]),
                "tool_call_count": tool_call_count,
                "ipi_injected_count": ipi_injected_count,
                "ts": utc_now_iso(),
            })

        print(f"    [OK] → {log_path.name} (turns={len(task['turns'])}, tools={tool_call_count}, ipi={ipi_injected_count})")
        return True

    except Exception as e:
        print(f"    [ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SPECTRA-AP Stage 3 — 적대적 시나리오 실행 (multi-turn + STM/LTM)"
    )
    parser.add_argument("--agent", required=True, help="Agent ID")
    parser.add_argument("--date", default=None, help="Profile/tasks 날짜 (YYYY-MM-DD). 생략 시 latest")
    parser.add_argument("--threat", default=None, help="특정 위협/case만 정확 매칭 (예: T1, CS1)")
    parser.add_argument("--threat-prefix", default=None,
                        help="threat_id prefix 매칭 (예: 'CS' = 모든 case study, 'T' = 모든 위협)")
    parser.add_argument("--sub", default=None, help="특정 sub-scenario만 (예: T1-S1)")
    parser.add_argument("--scenario", default=None, help="특정 시나리오만 (예: T1-S1-S1)")
    parser.add_argument("--generated-date", default=None,
                        help="시나리오 생성 날짜 (YYYY-MM-DD). 생략 시 최신 자동 감지.")
    parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    parser.add_argument("--configs-dir", default=str(DEFAULT_CONFIGS_DIR))
    parser.add_argument("--sleep", type=float, default=0.0, help="task 간 대기 (초)")
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    configs_dir = Path(args.configs_dir)

    # 1. config 로드
    config = load_config(configs_dir, args.agent)
    llm_cfg = config.get("llm", {})
    runner_cfg = config.get("runner", {})
    paths_cfg = config.get("paths", {})
    logging_cfg = config.get("logging", {})
    mcp_cfg = config.get("mcp", {})
    memory_cfg = config.get("memory", {})

    # 2. agent_profile
    profile_path = resolve_profile_path(DEFAULT_AGENT_PROFILES_DIR, args.agent, args.date)
    profile_date = profile_path.parent.name
    agent_profile = load_yaml(profile_path)

    # 3. system_prompt
    sp_path_str = paths_cfg.get("system_prompt")
    if sp_path_str:
        sp = Path(sp_path_str)
        if not sp.is_absolute():
            sp = repo_root / sp
        system_prompt = sp.read_text(encoding="utf-8")
    else:
        system_prompt = agent_profile.get("system_prompt", "")

    # 4. tasks.jsonl (v3 경로: <profile_date>/<generated_date>/tasks.jsonl)
    profile_tasks_root = DEFAULT_TASKS_ROOT / args.agent / profile_date
    if not profile_tasks_root.exists():
        print(f"[ERROR] tasks dir not found: {profile_tasks_root}", file=sys.stderr)
        sys.exit(1)

    # generated_date 자동 감지 (가장 최신)
    if args.generated_date:
        generated_date = args.generated_date
    else:
        gen_dates = sorted([d.name for d in profile_tasks_root.iterdir()
                            if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name)])
        if not gen_dates:
            print(f"[ERROR] no generated_date dir found under {profile_tasks_root}", file=sys.stderr)
            sys.exit(1)
        generated_date = gen_dates[-1]

    tasks_path = profile_tasks_root / generated_date / "tasks.jsonl"
    if not tasks_path.exists():
        print(f"[ERROR] tasks.jsonl not found: {tasks_path}", file=sys.stderr)
        sys.exit(1)
    all_tasks = read_jsonl(tasks_path)

    tasks = all_tasks
    if args.threat:
        tasks = [t for t in tasks if t.get("threat_id") == args.threat]
    if args.threat_prefix:
        tasks = [t for t in tasks if t.get("threat_id", "").startswith(args.threat_prefix)]
    if args.sub:
        tasks = [t for t in tasks if t.get("sub_id") == args.sub]
    if args.scenario:
        tasks = [t for t in tasks if t.get("id") == args.scenario]
    if not tasks:
        print(f"[ERROR] no tasks matched filters "
              f"(threat={args.threat}, sub={args.sub}, scenario={args.scenario})",
              file=sys.stderr)
        sys.exit(1)

    # 5. server.py import + 도구 dispatch
    server_module = import_server_module(repo_root, args.agent, mcp_cfg)
    tool_dispatch = server_module.list_public_tools()

    # 6. 시드 빌드
    seed_dir_str = (memory_cfg.get("ltm") or {}).get("seed_dir") or \
                   f"scenarios/{args.agent}/memory_store/seed"
    seed_dir = Path(seed_dir_str)
    if not seed_dir.is_absolute():
        seed_dir = repo_root / seed_dir
    seed_index_dir = DEFAULT_LTM_ROOT / args.agent / "_seed" / "default"
    print(f"[SEED] building / checking seed index ...")
    seed_result = server_module.build_seed_index(seed_dir, seed_index_dir)
    print(f"[SEED] {seed_result}")

    logs_root = Path(logging_cfg.get("base_dir") or "outputs/logs")
    if not logs_root.is_absolute():
        logs_root = repo_root / logs_root

    print(f"[INFO] agent={args.agent} profile_date={profile_date} generated_date={generated_date}")
    print(f"[INFO] tasks={len(tasks)} (filtered from {len(all_tasks)})")
    print(f"[INFO] llm={llm_cfg.get('provider')}/{llm_cfg.get('model')}")
    print(f"[INFO] logs_root={logs_root}")
    print(f"[INFO] tool_count={len(tool_dispatch)}")
    print()

    # 7. 각 task 순차 실행
    ok_count = 0
    fail_count = 0
    for i, task in enumerate(tasks, 1):
        task_id = task["id"]
        print(f"[{i}/{len(tasks)}] {task_id} ({task.get('turn_mode')}, {task.get('injection_vector')})")
        try:
            success = run_one_task(
                task=task, system_prompt=system_prompt, agent_profile=agent_profile,
                llm_cfg=llm_cfg, runner_cfg=runner_cfg, repo_root=repo_root,
                ltm_root=DEFAULT_LTM_ROOT, logs_root=logs_root,
                server_module=server_module, seed_index_dir=seed_index_dir,
                profile_date=profile_date, generated_date=generated_date,
                tool_dispatch=tool_dispatch,
            )
            if success:
                ok_count += 1
            else:
                fail_count += 1
        except Exception as e:
            fail_count += 1
            print(f"  [FATAL] {task_id}: {type(e).__name__}: {e}", file=sys.stderr)

        if args.sleep > 0:
            time.sleep(args.sleep)

    print()
    print(f"[SUMMARY] success={ok_count}, fail={fail_count}, total={len(tasks)}")
    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
