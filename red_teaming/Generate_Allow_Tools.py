#!/usr/bin/env python3
"""CCS allow_tool.json generator: connect to each agent's MCP server, fetch tool list, write generated_tasks/{agent}/{date}/allow_tool.json."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def repo_root_from_this_file() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def discover_agents(agent_profiles_dir: Path) -> List[str]:
    if not agent_profiles_dir.exists():
        return []
    agents = []
    for d in sorted(agent_profiles_dir.iterdir()):
        if d.is_dir() and not d.name.startswith("."):
            agents.append(d.name)
    return agents


def get_latest_profile_date(agent_profiles_dir: Path, agent: str) -> Optional[str]:
    base = agent_profiles_dir / agent
    if not base.exists():
        return None
    dates = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name):
            dates.append(d.name)
    return dates[-1] if dates else None


async def fetch_tools_from_mcp(
    server_path: Path,
    python_executable: str,
) -> List[Dict[str, Any]]:
    """Connect to the MCP server and fetch tool names with descriptions."""
    params = StdioServerParameters(
        command=python_executable,
        args=[str(server_path)],
        env=os.environ.copy(),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            raw_tools = getattr(result, "tools", []) or []

    tools = []
    for t in raw_tools:
        tools.append({
            "name": t.name,
            "description": getattr(t, "description", "") or "",
        })
    return tools


def classify_tool_role(name: str, description: str) -> Dict[str, str]:
    """Infer role/trust_level from tool name and description."""
    n = name.lower()
    d = description.lower()

    if "kb_search" in n or "kb" in n and "search" in d:
        return {"role": "rag", "trust_level": "trusted_internal_kb"}

    return {"role": "baseline", "trust_level": "trusted_internal"}


def build_allow_tool_data(
    agent: str,
    tools: List[Dict[str, Any]],
) -> Dict[str, Any]:
    tool_names = [t["name"] for t in tools]

    tool_policy = {}
    for t in tools:
        policy = classify_tool_role(t["name"], t["description"])
        tool_policy[t["name"]] = policy

    return {
        "mcp_server": {
            "command": "python",
            "args": [f"mcp_servers/{agent}/server.py"]
        },
        "allowed_tools": tool_names,
        "tool_policy": tool_policy,
    }


async def process_one_agent(
    *,
    repo_root: Path,
    agent: str,
    profile_date: str,
    python_executable: str,
) -> Path:
    server_path = repo_root / "mcp_servers" / agent / "server.py"
    if not server_path.exists():
        raise FileNotFoundError(f"server.py not found: {server_path}")

    tools = await fetch_tools_from_mcp(server_path, python_executable)

    if not tools:
        raise RuntimeError(f"Failed to fetch tools from MCP server: {agent}")

    data = build_allow_tool_data(agent, tools)

    out_dir = repo_root / "red_teaming" / "generated_tasks" / agent / profile_date
    ensure_dir(out_dir)

    out_path = out_dir / "allow_tool.json"
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return out_path


async def async_main() -> int:
    parser = argparse.ArgumentParser(description="CCS allow_tool.json batch generator (connects to MCP server)")
    parser.add_argument("--agent", default="", help="Process only a specific agent. If not specified, process all.")
    parser.add_argument("--date", default="", help="Profile date. If not specified, the latest is automatically selected.")
    parser.add_argument("--repo-root", default="", help="Project root. If not specified, auto-detected.")
    parser.add_argument("--python", default=sys.executable, help="Path to Python executable for running MCP server.py.")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser() if args.repo_root.strip() else repo_root_from_this_file()
    agent_profiles_dir = repo_root / "red_teaming" / "agent_profiles"

    if not agent_profiles_dir.exists():
        print(f"[ERROR] agent_profiles_dir not found: {agent_profiles_dir}")
        return 1

    if args.agent.strip():
        agents = [args.agent.strip()]
    else:
        agents = discover_agents(agent_profiles_dir)
        if not agents:
            print(f"[ERROR] No agents found in {agent_profiles_dir}")
            return 1

    print(f"{'='*60}")
    print(f"Generating CCS allow_tool.json (connecting to MCP server)")
    print(f"  agents: {len(agents)}")
    print(f"  python: {args.python}")
    print(f"{'='*60}\n")

    ok = 0
    fail = 0

    for agent in agents:
        if args.date.strip():
            date = args.date.strip()
        else:
            date = get_latest_profile_date(agent_profiles_dir, agent)

        if not date:
            print(f"[SKIP] {agent}: no profile date found")
            fail += 1
            continue

        try:
            out_path = await process_one_agent(
                repo_root=repo_root,
                agent=agent,
                profile_date=date,
                python_executable=args.python,
            )

            data = json.loads(out_path.read_text(encoding="utf-8"))
            n_tools = len(data.get("allowed_tools", []))
            tool_names = ", ".join(data.get("allowed_tools", []))

            print(f"[OK] {agent} ({date}): {n_tools} tools")
            print(f"     → {out_path}")
            print(f"     Tools: {tool_names}\n")
            ok += 1

        except Exception as e:
            print(f"[ERROR] {agent}: {e}\n")
            fail += 1

    print(f"{'='*60}")
    print(f"Complete: success={ok}, fail={fail}, total={len(agents)}")

    return 0 if fail == 0 else 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
