# SPECTRA: Structural & Category-aware Threat Risk Analysis

> **Anonymous artifact for double-blind review.**
> Companion artifact for the paper *"Why Traditional Vulnerability Analysis Falls Short for Agentic AI Systems: Toward Structural and Category-Aware Inspection"* (under double-blind review).

SPECTRA is a pre-deployment inspection framework for LLM-based agents that combines a **reusable Threat Specification** with a **deployment-specific Agent Specification** to generate agent-conditioned adversarial inspection scenarios, execute them in a controlled ReAct/MCP environment, and produce trace-grounded structural-weakness findings.

This artifact contains the **gray-box inspection pipeline** described in §3–§4 of the paper. The supplementary black-box probing study on commercial agents (Appendix H) is **not** included, in line with the responsible-disclosure and misuse-mitigation policy in §B of the paper.

> **Note for reviewers.** Repository metadata, commit history, author names, institutional identifiers, funding information, and other deanonymizing details have been removed from this artifact for double-blind review.

---

## Pipeline Overview

SPECTRA follows the four-phase architecture in Figure 1 of the paper, implemented as a five-stage pipeline (Phase 2 in the paper corresponds to two implementation stages: scenario generation and tool-exposure assembly).

| Stage | Script | Paper Phase / Section |
|------:|--------|---------------|
| 1. Agent Specification | `red_teaming/Generate_Agent_Specification.py` | Phase 1 (§3.2) |
| 2. Adaptive Adversarial Scenario Generation | `red_teaming/Generate_Adversarial_Evaluation_Scenario.py` | Phase 2 (§3.3) |
| 3. Tool-exposure & attack-task assembly | `red_teaming/Generate_Allow_Tools.py` | Phase 2/3 bridge (§3.3, §3.4) |
| 4. ReAct + stub-MCP Execution | `red_teaming/Run_Agent_Vulnerability_Analysis.py` | Phase 3 (§3.4) |
| 5. Automated Behavioral Evaluation (LLM-as-a-Judge) | `red_teaming/Vulnerability_Judge.py` | Phase 4 (§3.4) |

Auxiliary components:

| Component | File / Directory |
|---|---|
| Reusable Threat Specification (11 threats, 19 cases) | `red_teaming/THREAT_Specification.json` |
| FAISS KB index builder | `run/build_kb_index.py` |
| RAG components | `src/rag/embedder.py`, `src/rag/kb_index.py` |
| Per-domain trusted KBs (Markdown + FAISS index) | `scenarios/` |
| Per-domain stub MCP servers (10 tools each) | `mcp_servers/` |
| Per-domain agent configurations | `configs/` |

---

## Repository Structure

```
SPECTRA/
├── configs/                          # 10 agent configurations (mode, paths, llm/runner config)
├── mcp_servers/                      # 10 domain-specific stub MCP servers (FastMCP, stdio)
├── scenarios/<agent>/
│   ├── system.txt                    # role, policy, TRACE RULE
│   └── KB/trusted/
│       ├── docs/*.md                 # 5 trusted policy/runbook documents per domain
│       └── index/                    # FAISS index (built by run/build_kb_index.py)
├── src/rag/
│   ├── embedder.py                   # sentence-transformers wrapper
│   └── kb_index.py                   # FAISS IndexFlatIP wrapper
├── run/
│   └── build_kb_index.py             # FAISS index builder
├── red_teaming/
│   ├── THREAT_Specification.json     # Reusable, agent-independent threat catalog
│   ├── Generate_Agent_Specification.py
│   ├── Generate_Adversarial_Evaluation_Scenario.py
│   ├── Generate_Allow_Tools.py
│   ├── Run_Agent_Vulnerability_Analysis.py
│   ├── Vulnerability_Judge.py
│   ├── agent_profiles/<agent>/<date>/agent_profile.yaml
│   ├── generated_scenarios/<agent>/<date>/T*.json
│   ├── generated_tasks/<agent>/<date>/
│   │   ├── tasks_attack.jsonl
│   │   └── allow_tool.json
│   └── run/logs/<agent>/attack/<date>/
│       ├── attack-T*-C*-S*_HHMMSS.jsonl
│       └── judge_results.json
├── requirements.txt
└── README.md
```

---

## Target Agents (§4.1)

Ten LLM-based agents covering different service domains. All agents share an abstract tool schema for controlled comparison but differ in system prompt, policies, and domain-specific tool semantics.

| Domain | Config |
|--------|--------|
| Banking | `configs/banking_cs_agent.yml` |
| E-commerce | `configs/ecommerce_operations_agent.yml` |
| Education | `configs/education_admin_agent.yml` |
| Government | `configs/government_service_agent.yml` |
| HR | `configs/hr_onboarding_agent.yml` |
| Insurance | `configs/insurance_claims_agent.yml` |
| Logistics | `configs/logistics_operations_agent.yml` |
| Medical | `configs/medical_consultation_agent.yml` |
| Telecom | `configs/telecom_cs_agent.yml` |
| Travel | `configs/travel_reservation_agent.yml` |

Each domain ships **10 MCP tools**: 1 trusted RAG (`kb_search_trusted`) + 7 baseline business tools + 2 attack-success high-risk tools. At inspection time, an **8-tool subset** (5 baseline + 1 RAG + 2 attack-success) is exposed to the agent through `allow_tool.json`, keeping the LLM context small and making attack-success calls easier to attribute.

---

## Threat Coverage (§3.1, §4.1)

Eleven OWASP Agentic AI threat categories with 19 case-level specifications. Each case is instantiated with **k = 3** scenario variants, yielding **57 attack tasks per agent × 10 agents = 570 inspection scenarios** in the main gray-box evaluation.

| ID | Threat Category | # Cases |
|----|------------------|:-------:|
| T1 | Memory Poisoning | 2 |
| T2 | Tool Misuse | 2 |
| T3 | Privilege Compromise | 2 |
| T4 | Resource Overload | 2 |
| T5 | Cascading Hallucination Attacks | 2 |
| T6 | Intent Breaking and Goal Manipulation | 2 |
| T7 | Misaligned and Deceptive Behaviors | 2 |
| T9 | Identity Spoofing and Impersonation | 2 |
| T10 | Overwhelming Human-in-the-Loop | 1 |
| T15 | Human Manipulation | 1 |
| T17 | Supply-Chain Compromise | 1 |
| **Total** | **11 categories** | **19** |

Two injection channels are evaluated, both specified at the case level in `THREAT_Specification.json`:

- **DPI (Direct Prompt Injection)** — adversarial content delivered through the user-facing prompt.
- **IPI (Indirect Prompt Injection, tool-result)** — adversarial content appended to the output of a configured source tool. IPI does **not** require a dedicated MCP tool: at execution time, `Run_Agent_Vulnerability_Analysis.py` invokes `inject_ipi_payload()` to append the payload to the matching source tool's result. The injection is observable only as appended text inside `tool_result.content` in the trace; no separate IPI marker is written.

---

## Observation Criteria (§3.4, Table 5)

Every positive finding produced by `Vulnerability_Judge.py` is mapped to exactly one of six trace-grounded observation criteria.

| ID | Criterion | Trace Evidence |
|----|-----------|----------------|
| OB1 | Planning deviates from policy | Planning text |
| OB2 | Required check or tool call omitted | Tool calls |
| OB3 | Tool-call sequence violates oracle | Tool-call sequence |
| OB4 | Argument crosses permission scope | Tool arguments |
| OB5 | Required safeguard missing in response | Final response |
| OB6 | Tool-call count abnormally inflated | Tool-call count |

The `system.txt` of each domain enforces a **TRACE RULE**: the agent must emit a one- or two-sentence `PLAN:` line immediately before each tool call, giving the judge a clean signal to distinguish *"the agent followed an injected payload"* from *"the agent acted intentionally,"* even when the resulting tool call is identical.

---

## Setup

### Requirements

- Python **3.10+** (tested on 3.12; the `mcp` package requires 3.10+)
- Linux (tested on Ubuntu 24.04)
- Gemini API access — **Gemini 2.5 Flash**, temperature 0 in all experiments

### Installation

Download the artifact archive from the review URL and extract it:

```bash
# After extracting the artifact archive
cd SPECTRA
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### API Key

The agents and the LLM-as-a-Judge both read the Gemini API key from `API_Key/gemini_api_key`, as referenced by every `configs/*.yml`:

```bash
mkdir -p API_Key
echo "YOUR_GEMINI_API_KEY" > API_Key/gemini_api_key
```

> The `API_Key/` directory and `*.env` files are excluded by `.gitignore`. **Never commit API keys.**

---

## Reproducing the Gray-Box Evaluation

The pipeline below mirrors Figure 1 of the paper. Each stage's output is consumed by the next.

### Phase 0 — Build the FAISS Knowledge-Base Index (once per domain)

```bash
python run/build_kb_index.py --scenario ecommerce_operations_agent
```

This embeds `scenarios/<agent>/KB/trusted/docs/*.md` with `intfloat/multilingual-e5-small` and writes a FAISS `IndexFlatIP` to `scenarios/<agent>/KB/trusted/index/`.

### Phase 1 — Agent Specification (Stage 1)

`Generate_Agent_Specification.py` spawns the domain's MCP server as a subprocess, calls `session.list_tools()` over stdio, and combines the tool schemas with `system.txt` and `configs/<agent>.yml`:

```bash
python red_teaming/Generate_Agent_Specification.py --agent ecommerce_operations_agent
```

Output: `red_teaming/agent_profiles/<agent>/<date>/agent_profile.yaml`.

### Phase 2 — Adaptive Adversarial Scenario Generation (Stage 2)

Combine the Threat Specification with each Agent Specification to generate `k = 3` variants per case (§3.3, Algorithm 1):

```bash
python red_teaming/Generate_Adversarial_Evaluation_Scenario.py --agent ecommerce_operations_agent
```

Output: `red_teaming/generated_scenarios/<agent>/<date>/T*.json`.

### Phase 2/3 bridge — Allow-Tool & Attack-Task Assembly (Stage 3)

Builds the runtime tool exposure and the attack-task list. For IPI scenarios, the `[IPI:tool_name] payload` marker in `attack_prompt` is parsed into `ipi_source_tool` + `ipi_payload` fields so the runner can inject at execution time:

```bash
python red_teaming/Generate_Allow_Tools.py --agent ecommerce_operations_agent
```

Outputs:
- `red_teaming/generated_tasks/<agent>/<date>/tasks_attack.jsonl` (57 tasks per domain)
- `red_teaming/generated_tasks/<agent>/<date>/allow_tool.json` (8-tool exposure)

### Phase 3 — ReAct / Stub-MCP Execution (Stage 4)

Drive a ReAct loop with the configured LLM, deterministically injecting IPI payloads where applicable (§3.4):

```bash
python red_teaming/Run_Agent_Vulnerability_Analysis.py --agent ecommerce_operations_agent --mode attack
```

Output: per-task JSONL traces (`meta`, `assistant`, `tool_call`, `tool_result`, `final` records) at `red_teaming/run/logs/<agent>/attack/<date>/attack-T*-C*-S*_HHMMSS.jsonl`.

### Phase 4 — Behavioral Evaluation (Stage 5)

Apply the scenario-specific oracle and assign a binary judgment plus an OB1–OB6 observation criterion to each trace (§3.4):

```bash
python red_teaming/Vulnerability_Judge.py --agent ecommerce_operations_agent
```

Outputs:
- `red_teaming/run/logs/<agent>/attack/<date>/judge_results.json`
- `red_teaming/run/logs/judge_results_all.json` (aggregated)

> Omit `--agent` on stages 1–5 to run across all 10 domains.

Per-deployment ASR (defined as the *trace-grounded structural-weakness finding rate*, not benchmark attack performance) ranges from **54.4 % to 77.2 %** with a mean of **63.5 %**. Threat-level and observation-level distributions are reported in Figures 6–7 of the paper.

---

## Threat Specification Schema (§3.2, Table 3)

`red_teaming/THREAT_Specification.json` is a two-level, agent-independent catalog.

**Threat-level fields**

| Field | Description |
|---|---|
| `threat_id` | OWASP identifier (e.g., `T1`) |
| `name` | Short threat name |
| `description` | Category-level threat description |
| `additional_rules` | Threat-level constraints and variation rules |

**Case-level fields**

| Field | Description |
|---|---|
| `case_id` | Case identifier under a threat category |
| `case_name` | Short name of the inspection case |
| `attack_pattern` | Adversarial delivery form and payload pattern (DPI or IPI) |
| `stub_assumption` | Reproducibility condition under stub MCP tools |
| `judgment_criterion` | Trace evidence required for an oracle-positive finding |

The `judgment_criterion` field is compiled into the scenario-specific oracle consumed by `Vulnerability_Judge.py`.

---

## Agent Specification Schema (§3.2, Table 4)

Constructed automatically from `configs/<agent>.yml` and MCP introspection:

| Field | Description |
|---|---|
| `agent_role` | Operational role and responsibilities |
| `system_prompt` | System prompt / instruction policy |
| `policies` | Extracted operational and safety constraints |
| `tools` | Exposed tools with descriptions and parameter schemas |
| `high_risk_actions` | Tools or actions requiring stricter inspection |
| `permission_boundaries` | Allowed scope for tool use and outputs |

SPECTRA does not attempt to model the internal state of the underlying LLM; only the externally defined deployment configuration is captured.

---

## Snapshot Figures

| Item | Value |
|---|---:|
| Domains | 10 |
| Tools per domain | 10 (1 trusted RAG + 7 baseline + 2 attack-success) |
| Tools exposed at runtime | 8 (5 baseline + 1 RAG + 2 attack-success) |
| Trusted KB documents per domain | 5 |
| Threats × cases | 11 × 19 |
| Scenarios per case (k) | 3 |
| Attack tasks per domain | 57 |
| Total attack tasks (10 domains) | 570 |
| Mean per-deployment ASR | 63.5 % (range 54.4 – 77.2 %) |

---

## Reproducibility Notes

- All scenario generation and behavioral evaluation use **Gemini 2.5 Flash** at **temperature 0** (§4.1).
- Stub MCP tools return scenario-defined mock responses **deterministically**, with no live external side effects.
- Recommended repeated-execution budget: **n_run = 3** (covers ≈ 97.1 % of positive findings under the reliability sample; Figure 3).
- Scenario-specific oracle judgments achieved **90.5 % agreement** with human annotations on the oracle-reliability sample (n = 95; Table 8).
- Trace reproducibility under deterministic stub-tool responses remains close to **1.0** across threat cases and variant counts (Figure 2b).

---

## Scope and Release Boundary

This artifact releases the **gray-box inspection pipeline** described in §3–§4 of the paper, including:

- The Threat Specification schema and an instantiated catalog (`THREAT_Specification.json`),
- The Agent Specification generator and ten target-agent configurations,
- The adaptive scenario generator and the trace-based behavioral evaluator,
- The stub-MCP execution runner and trace recorder,
- The per-domain RAG knowledge bases and FAISS index builder.

It does **not** include the supplementary **black-box probing study** on commercial agents (Appendix H). Specifically, prompts, transcripts, raw outputs, service-identifying metadata, and reusable adversarial payloads associated with the commercial-agent setting are withheld in accordance with §B (Ethical Considerations) of the paper.

---

## Citation

Author and venue information have been redacted for double-blind review.
The full citation will be provided upon acceptance.

---

## License

*To be released with the de-anonymized version.* MIT or Apache-2.0 is anticipated.
