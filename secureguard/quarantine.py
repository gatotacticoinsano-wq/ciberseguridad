import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from secureguard.config import DEFAULT_QUARANTINE_DIR


class QuarantineManager:
    def __init__(self, quarantine_dir: Path | None = None):
        self.quarantine_dir = quarantine_dir or DEFAULT_QUARANTINE_DIR
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def quarantine(self, source_path: Path) -> Optional[Path]:
        if not source_path.exists() or not source_path.is_file():
            return None

        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        destination = self.quarantine_dir / f"{source_path.stem}-{timestamp}{source_path.suffix}"

        try:
            shutil.copy2(source_path, destination)
            return destination
        except OSError:
            return None

    def list_quarantine(self) -> list[Path]:
        return [path for path in self.quarantine_dir.iterdir() if path.is_file()]
