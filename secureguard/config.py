from pathlib import Path
from typing import Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGNATURE_FILE = PROJECT_ROOT / "signatures.txt"
DEFAULT_QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
LOG_FILE = PROJECT_ROOT / "secureguard.log"

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".wsf",
    ".msi",
    ".dll",
}

KNOWN_SAFE_EXTENSIONS = {
    ".txt",
    ".md",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
}


def load_signatures() -> List[str]:
    if not SIGNATURE_FILE.exists():
        return []

    signatures = []
    for line in SIGNATURE_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        signatures.append(item)
    return signatures


def normalize_path(path: str) -> Path:
    return Path(path).expanduser().resolve()
