#!/usr/bin/env bash
set -euo pipefail

# Generic, publishable leak check over the tracked tree. Organization-specific
# names are supplied through OSS_DENYLIST_FILE (default:
# scripts/oss-denylist.local), which is never committed. See
# scripts/oss_safety_check.py for the checks themselves.
exec python3 "$(dirname "$0")/oss_safety_check.py"