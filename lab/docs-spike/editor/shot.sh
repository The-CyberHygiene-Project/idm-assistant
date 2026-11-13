#!/usr/bin/env bash
# editor/shot.sh OUT.png : screenshot of the workstation's Xvfb :77 (RUNS ON THE MAC)
cd "$(dirname "$0")/.."; ssh -F ssh_config dcli 'cat ~/fb/Xvfb_screen0' > /tmp/shot.xwd && python3 -I editor/xwd2png.py /tmp/shot.xwd "$1"
