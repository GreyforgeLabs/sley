#!/usr/bin/env python3
"""Fail closed for product gates whose implementation has not landed."""

from __future__ import annotations

import json
import sys


gate = sys.argv[1] if len(sys.argv) > 1 else "unknown"
print(json.dumps({
    "gate": gate,
    "phase": "M0",
    "result": "NOT_IMPLEMENTED",
    "reason": "The M0 constitutional baseline contains no semantic kernel.",
}, sort_keys=True))
raise SystemExit(2)
