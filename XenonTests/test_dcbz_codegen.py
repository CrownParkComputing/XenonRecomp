#!/usr/bin/env python3
"""Pin ordinary Xenon dcbz to a 128-byte aligned, 128-byte clear."""

import re
import sys
from pathlib import Path


source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"case PPC_INST_DCBZ:(?P<body>.*?)case PPC_INST_DCBZL:",
    source,
    flags=re.DOTALL,
)
if not match:
    raise SystemExit("ordinary DCBZ emission block was not found")
body = match.group("body")
if 'println("{}.u32) & ~127), 0, 128);"' not in body:
    raise SystemExit("ordinary DCBZ does not emit a 128-byte aligned 128-byte clear")
if "~31" in body or ", 0, 32" in body:
    raise SystemExit("ordinary DCBZ still contains generic 32-byte semantics")
print("ordinary Xenon dcbz: 128-byte alignment and clear pinned")
