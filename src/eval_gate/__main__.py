# coding: utf-8
"""``python -m eval_gate`` → cli.main（ci/run-tier.sh 的调用形态）."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
