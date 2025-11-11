"""Developer runner that works without installing the package.

Adds the local `src` to `sys.path` so imports resolve in-place.
"""
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from haven_tftp.app import main  # noqa: E402


if __name__ == "__main__":
    main()
