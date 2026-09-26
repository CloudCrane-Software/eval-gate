# coding: utf-8
"""pytest 公共配置：src 布局兜底（pyproject 的 pythonpath 已覆盖，双保险）."""
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
