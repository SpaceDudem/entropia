# Ornith + Codex CLI — Local Uncensored Coding Agent

A fully local, uncensored AI coding agent. No API keys, no rate limits, no refusals. Runs entirely on your hardware.

**Stack:**
- [Ornith-1.0-35B](https://huggingface.co/AEON-7/Ornith-1.0-35B-AEON-Ultimate-Uncensored-BF16) — 35B MoE model, abliterated (refusals removed at weight level), BF16
- [vLLM](https://github.com/vllm-project/vllm) — high-throughput inference server
- [Codex CLI](https://github.com/openai/codex) — agentic coding harness with full shell access

---

## Hardware Tiers

### Tier 1 — Full (Recommended) · RunPod B200 / H200 / 2×A100 80GB
> 160–183GB VRAM · Full BF16 · 256K context

The reference configuration. Everything in this repo was built on a RunPod B200.

```bash
MAX_MODEL_LEN='262144'
GPU_MEMORY_UTILIZATION='0.92'
MAX_NUM_BATCHED_TOKENS='262144'
TENSOR_PARALLEL_SIZE='1'          # or '2' for 2×A100
```

**RunPod template:** Search for `NVIDIA B200` or `2×A100 80GB SXM`. Use the PyTorch 2.x image.

---

### Tier 2 — Mid · 1×A100 80GB / 1×H100 80GB
> 80GB VRAM · Full BF16 · 32K context

Weights fit (~70GB), context window is reduced to leave room for KV cache.

```bash
MAX_MODEL_LEN='32768'
GPU_MEMORY_UTILIZATION='0.88'
MAX_NUM_BATCHED_TOKENS='32768'
TENSOR_PARALLEL_SIZE='1'
```

Capable for most coding tasks. Loses long-file and large-codebase awareness.

---

### Tier 3 — Budget · 2×RTX 4090 / 2×RTX 3090 (48GB combined)
> 48GB VRAM · Q4 quantized · 8K–16K context

Requires a quantized version of the model. BF16 does not fit.
Use [bartowski's GGUF](https://huggingface.co/bartowski) or similar Q4_K_M quantization.
Serve with [llama.cpp](https://github.com/ggerganov/llama.cpp) or vLLM with AWQ.

```bash
# Switch MODEL_ID to a quantized variant, e.g.:
MODEL_ID='your-chosen-quantized-ornith-or-equivalent'
MAX_MODEL_LEN='8192'
GPU_MEMORY_UTILIZATION='0.90'
MAX_NUM_BATCHED_TOKENS='8192'
TENSOR_PARALLEL_SIZE='2'
```

---

### Tier 4 — Minimum · 1×RTX 4090 (24GB)
> 24GB VRAM · Q4 quantized · 4K–8K context

Use a smaller abliterated model entirely. Recommended alternatives:
- `Qwen/Qwen2.5-14B-Instruct` + abliteration patch
- Any 7B–14B uncensored model from HuggingFace

Context window this small limits multi-file work significantly.

---

## Setup

```bash
git clone https://github.com/SpaceDudem/entropia
cd entropia/template
chmod +x setup.sh
sudo ./setup.sh
```

For Tier 1 defaults, no edits needed. For other tiers, edit `config/env` before running.

---

## Starting vLLM

```bash
# In a persistent terminal (tmux/screen recommended)
/workspace/ornith-vllm/config/launch_command.sh &>> /workspace/ornith-vllm/logs/vllm-local.log &

# First start takes ~6 minutes (CUDA graph compilation)
# Watch the log:
tail -f /workspace/ornith-vllm/logs/vllm-local.log

# Confirm it's up:
curl http://127.0.0.1:8000/health
```

---

## Running Codex

```bash
codex
```

Codex connects to the local vLLM instance. No OpenAI API key required.

Verify everything is working:
```bash
codex doctor
codex exec "what is 2 + 2"
```

---

## What This Gives You

- **Uncensored**: Ornith will not refuse security research, red team tooling, exploit development, or any other task
- **Private**: Nothing leaves your machine
- **256K context**: Read entire codebases in a single session (Tier 1/2)
- **Tool use**: Full shell access — reads files, runs tests, edits code, commits to git
- **Reasoning**: Native chain-of-thought via `<think>` blocks

---

## Troubleshooting

**`codex doctor` shows auth failure**
The `OPENAI_API_KEY` env var must be set to *something* (value doesn't matter for local vLLM). Run:
```bash
export OPENAI_API_KEY=local
```
This is handled automatically by `setup.sh`.

**vLLM OOM on startup**
Reduce `GPU_MEMORY_UTILIZATION` to `0.85` and `MAX_MODEL_LEN` to match your tier.

**First startup takes forever**
Normal. CUDA graph compilation runs once per model/GPU combination. Subsequent starts on the same machine are faster if the compilation cache is warm.

**Codex completes tasks in <100ms with no output**
Check `codex doctor` — usually an auth issue. See above.
