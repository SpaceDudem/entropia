#!/usr/bin/env bash
# =============================================================================
# Ornith + Codex CLI — Full Setup Script
# Tested on: Ubuntu 22.04 / 24.04, CUDA 12.x
# =============================================================================
set -Eeuo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VLLM_DIR="$WORKSPACE/ornith-vllm"
MODEL_DIR="$VLLM_DIR/models/ornith-bf16"
LOG_DIR="$VLLM_DIR/logs"

echo "==> Creating directory structure"
mkdir -p "$VLLM_DIR"/{config,logs,hf/hub,models,state}
mkdir -p "$MODEL_DIR"

# =============================================================================
# 1. Python environment + vLLM
# =============================================================================
echo "==> Installing Python venv"
apt-get update -qq && apt-get install -y -qq python3-venv python3-pip git curl

python3 -m venv "$VLLM_DIR/venv"
source "$VLLM_DIR/venv/bin/activate"

echo "==> Installing vLLM and HF transfer"
pip install -q --upgrade pip
pip install -q vllm hf_transfer huggingface_hub

# =============================================================================
# 2. Download the model
# =============================================================================
echo "==> Downloading Ornith-1.0-35B-BF16 from HuggingFace"
echo "    This is ~70GB — go get a coffee."
echo ""
echo "    If you have a HF token (needed if repo is gated): export HF_TOKEN=hf_..."
echo ""

HF_HUB_ENABLE_HF_TRANSFER=1 \
HF_HOME="$VLLM_DIR/hf" \
  python3 -c "
from huggingface_hub import snapshot_download
snapshot_download(
    'AEON-7/Ornith-1.0-35B-AEON-Ultimate-Uncensored-BF16',
    local_dir='$MODEL_DIR',
    ignore_patterns=['*.pt', 'original/*'],
)
print('Download complete.')
"

# =============================================================================
# 3. Write vLLM config — edit these for your hardware tier (see README)
# =============================================================================
echo "==> Writing vLLM config"
cp "$(dirname "$0")/config/env" "$VLLM_DIR/config/env"
cp "$(dirname "$0")/config/launch_command.sh" "$VLLM_DIR/config/launch_command.sh"
chmod +x "$VLLM_DIR/config/launch_command.sh"

# =============================================================================
# 4. Install Codex CLI
# =============================================================================
echo "==> Installing Codex CLI"
if ! command -v npm &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi
npm install -g @openai/codex

# Remove bwrap — it blocks shell commands inside Codex sandbox
BWRAP_PATH=$(find /usr/lib/node_modules/@openai/codex -name "bwrap" -type f 2>/dev/null | head -1)
if [ -n "$BWRAP_PATH" ]; then
    echo "==> Removing bwrap sandbox binary: $BWRAP_PATH"
    rm -f "$BWRAP_PATH"
fi

# =============================================================================
# 5. Write Codex config
# =============================================================================
echo "==> Writing Codex config"
mkdir -p "$HOME/.codex"
cp "$(dirname "$0")/codex/config.toml" "$HOME/.codex/config.toml"

# =============================================================================
# 6. Persist environment
# =============================================================================
echo "==> Writing environment to /etc/environment"
echo 'OPENAI_API_KEY=local' >> /etc/environment

cat >> "$HOME/.bashrc" << 'EOF'

# Ornith vLLM environment
source /workspace/ornith-vllm/config/env
export OPENAI_API_KEY="${OPENAI_API_KEY:-local}"
EOF

# =============================================================================
# Done
# =============================================================================
echo ""
echo "============================================================"
echo "  Setup complete."
echo ""
echo "  Start vLLM:   $VLLM_DIR/config/launch_command.sh"
echo "  Check health: curl http://127.0.0.1:8000/health"
echo "  Run Codex:    codex"
echo ""
echo "  First startup takes ~6 minutes (CUDA graph compilation)."
echo "  Subsequent startups are faster IF the model stays cached."
echo "============================================================"
