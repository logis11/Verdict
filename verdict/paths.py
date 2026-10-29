"""Repository-root anchored locations for per-target data (state/, work/, reports/)."""
import os

# verdict/paths.py -> verdict/ -> repo root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
