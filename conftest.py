"""Make the project root importable so `pfc`, `vulnerable` and `governed`
resolve when pytest is run from anywhere in the tree."""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
