#!/bin/sh
# Hands each Claude Code hook event (JSON on stdin) to the Prismor CLI installed
# on this machine. Install it first with: pip install prismor
# Observe mode records and warns. Run `prismor setup` to choose enforce mode.
exec prismor hook-dispatch --agent claude --mode observe
