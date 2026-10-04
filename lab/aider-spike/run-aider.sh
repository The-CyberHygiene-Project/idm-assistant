#!/bin/bash
# run-aider.sh ARGS… : the ONLY way aider is run in this spike — inside a macOS sandbox that denies all outbound network
# except localhost (LM Studio), with update checks and analytics off. Any internet attempt fails (and is visible).
cd "$(dirname "$0")"
export OPENAI_API_BASE=http://127.0.0.1:1234/v1 OPENAI_API_KEY=lm-studio AIDER_ANALYTICS_DISABLE=1 AIDER_CHECK_UPDATE=false LITELLM_LOCAL_MODEL_COST_MAP=True
exec sandbox-exec -f sandbox.sb ./venv/bin/python "$@"
