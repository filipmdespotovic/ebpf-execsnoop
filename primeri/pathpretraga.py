#!/usr/bin/env python3
"""Namerno izaziva pretragu kroz PATH preko os.execvp."""
import os, sys

program = sys.argv[1] if len(sys.argv) > 1 else "grep"
print("Trazim:", program)
sys.stdout.flush()

os.execvp(program, [program, "--version"])

print("execvp nije uspeo")
sys.exit(127)
