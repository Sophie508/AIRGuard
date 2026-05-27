# AIRGuard

Contextual authority-risk control for LLM agent runtimes.

AIRGuard is a runtime defense that combines authority context, resource trust labels, LLM-based risk simulation, and tiered enforcement to protect LLM agents from indirect prompt injection attacks via untrusted tool outputs.

## Repository Structure

```
AIRGuard/
├── src/airguard/                      # Core defense implementation
│   ├── guard.py                       # Main check_action() pipeline
│   ├── enforcement.py                 # Tiered enforcement decisions
│   ├── authority_context.py           # Authority/capability mapping
│   ├── risk_simulation.py             # LLM-based risk simulation
│   ├── target_trust.py                # Resource trust scoring
│   ├── trust_labeling.py              # Trust tier assignment
│   └── integrations/
│       └── mcp_proxy.py               # MCP tool-call interception proxy
├── benchmarks/
│   └── dtap/                          # DTAP-150 benchmark interface
│       ├── agents/                    # CLI agent wrappers (claudecli, codexcli)
│       └── scripts/run_with_airguard.py  # Batch runner
├── data/
│   └── dtap150.jsonl                  # DTAP-150 task manifest (150 cases)
├── requirements.txt
├── LICENSE
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

Additional requirements:
- Python 3.11+
- Docker (for DTAP MCP servers)
- `claude` CLI v2.1+ (for Claude models) or `codex` CLI v0.130+ (for GPT models)

## Authentication

| Model | CLI | Setup |
|---|---|---|
| Claude Haiku 4.5 / Sonnet 4.6 | `claude` | `claude auth login` |
| GPT-5.4-mini / GPT-5.3-codex | `codex` | `codex login` |

## Running Experiments

### DTAP-150

DTAP-150 consists of 150 tasks (100 malicious + 50 benign) across 5 domains: code, finance, legal, os-filesystem, and telecom. Each domain has MCP servers providing domain-specific tools.

```bash
export DTAP_ROOT=/path/to/dtap          # Your DTAP installation
export AIRGUARD_ENABLED=1
export PYTHONPATH=$DTAP_ROOT:src

python benchmarks/dtap/scripts/run_with_airguard.py \
  --selected-tasks data/dtap150.jsonl \
  --agent-type claudecli \
  --model claude-haiku-4-5-20251001 \
  --output-root results/airguard_haiku
```

For GPT models, use `--agent-type codexcli` and `--model gpt-5.4-mini`.

## Data

`data/dtap150.jsonl` contains the 150-case subset manifest for DTAP-150 (100 malicious + 50 benign, 5 domains). Each line is a JSON object with fields:

| Field | Description |
|---|---|
| `domain` | Task domain (code, finance, legal, os-filesystem, telecom) |
| `type` | `benign` or `malicious` |
| `task_id` | Numeric task identifier within the domain |
| `threat_model` | Attack type for malicious tasks (direct, indirect) |
| `subtype` | Attack subtype (e.g., Add-risky-alias, credential_leak) |

The full DTAP benchmark environment (MCP servers, task fixtures, judge scripts) is available from the DTAP benchmark repository.

## Baseline Methods

This repository contains only the implementation of AIRGuard. The baseline defense methods compared in the paper are:

- **ARGUS** — see [Phuong et al., 2025](https://arxiv.org/abs/2605.03378)
- **MELON** — see [Zhu et al., 2025](https://github.com/kaijiezhu11/MELON)

To reproduce baseline comparisons, please refer to the original repositories of these methods.

## License

MIT License. See [LICENSE](LICENSE).
