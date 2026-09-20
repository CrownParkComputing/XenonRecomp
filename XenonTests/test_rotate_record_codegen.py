#!/usr/bin/env python3
"""Require MD-form rotate record instructions to update CR0."""

import re
import sys
from pathlib import Path


source = Path(sys.argv[1]).read_text(encoding="utf-8")
for opcode, following in (
    ("RLDICL", "RLDICR"),
    ("RLDICR", "RLDIMI"),
    ("RLDIMI", "RLWIMI"),
):
    match = re.search(
        rf"case PPC_INST_{opcode}:(?P<body>.*?)case PPC_INST_{following}:",
        source,
        flags=re.DOTALL,
    )
    if not match:
        raise SystemExit(f"{opcode} emission block was not found")
    body = match.group("body")
    if "strchr(insn.opcode->name, '.')" not in body:
        raise SystemExit(f"{opcode} does not test the record bit")
    if "compare<int64_t>" not in body or "cr(0)" not in body:
        raise SystemExit(f"{opcode} record form does not emit a CR0 comparison")

print("MD-form rotate record instructions update CR0")
