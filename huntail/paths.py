"""Repository-root anchored locations for per-target data (state/, work/, reports/)."""
import os

# huntail/paths.py -> huntail/ -> repo root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
