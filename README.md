# BitGN PAC Agent

OpenAI (ChatGPT) agent for [BitGN PAC](https://bitgn.com) competition. 84% on pac1-dev (21/25).

## Setup

```bash
# 1. Install uv (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Install dependencies
cd agent
uv sync

# 3. Generate protobuf SDK from proto files
uv run python -m grpc_tools.protoc \
  -I../sample-agents/proto \
  --python_out=. \
  bitgn/harness.proto \
  bitgn/vm/pcm.proto \
  bitgn/vm/mini.proto

# 4. Copy .env and set your API key
cp .env.example .env
# Edit .env — set OPENAI_API_KEY
```

## Run

```bash
# All tasks
uv run python main.py

# Single task
uv run python main.py t03

# Multiple tasks
uv run python main.py t07 t13 t19
```

## Configuration (.env)

```
OPENAI_API_KEY=sk-...           # https://platform.openai.com/api-keys
# OPENAI_BASE_URL=...           # Optional — proxies / non-default endpoints only
MODEL=gpt-4o                    # e.g. gpt-4o-mini
BENCHMARK_HOST=https://api.bitgn.com
BENCHMARK_ID=bitgn/pac1-dev     # or bitgn/pac1-prod on competition day
MAX_STEPS=40                    # Max agent steps per task
```

## Architecture

```
main.py          Harness client — connects to BitGN, iterates tasks, collects scores
agent.py         3-phase agent: bootstrap → execute loop → report
tools.py         11 PcmRuntime tools + dispatch + shell-like formatting
security.py      28+ injection patterns, secret detection, SecurityGate
bitgn/           ConnectRPC clients + protobuf stubs (generated from proto)
notes/           Analysis, insights, run logs
```

### Agent loop

1. **Bootstrap** — `tree /` + `read AGENTS.md` + `context()` before every task
2. **Execute** — Claude native tool_use loop (max 40 steps) with:
   - Code-level security gate (blocks path traversal, mass deletion, secret leaks)
   - Content scanner (injection detection after every `read`/`search`)
   - Stagnation detector (same tool called 3x → warning)
   - Context pruner (keeps bootstrap + recent messages when history grows)
3. **Report** — `report_completion` with outcome + grounding refs

### Security layers

- **Prompt**: authority hierarchy (L1 system > L2 AGENTS.md > L3 task > L4 nested > L5 file content)
- **Code**: SecurityGate blocks dangerous operations before dispatch
- **Scanner**: 28+ regex patterns + Unicode normalization + base64 decoding on file content
- **Gate on output**: blocks secrets in answers and file writes
