#!/usr/bin/env bash
set -Eeuo pipefail

source '/workspace/ornith-vllm/venv/bin/activate'
source '/workspace/ornith-vllm/config/env'

exec vllm serve "${MODEL_ID}" \
  --served-model-name "${SERVED_MODEL_NAME}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --trust-remote-code \
  --tensor-parallel-size "${TENSOR_PARALLEL_SIZE}" \
  --max-model-len "${MAX_MODEL_LEN}" \
  --gpu-memory-utilization "${GPU_MEMORY_UTILIZATION}" \
  --max-num-batched-tokens "${MAX_NUM_BATCHED_TOKENS}" \
  --enable-prefix-caching \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml \
  --reasoning-parser qwen3 \
  --chat-template /workspace/ornith-vllm/models/ornith-bf16/chat_template.jinja
