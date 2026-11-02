"""Launch LinkShield without opening a console window on Windows."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from phishing_detector.gui import run


if __name__ == "__main__":
    run()
