import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from secureguard.config import DEFAULT_QUARANTINE_DIR, load_signatures, SUSPICIOUS_EXTENSIONS, KNOWN_SAFE_EXTENSIONS


@dataclass
class Detection:
    path: Path
    signatures: List[str] = field(default_factory=list)
    heuristics: List[str] = field(default_factory=list)


@dataclass
class ScanReport:
    scanned_files: int
    detections: List[Detection]
    duration_seconds: float


class Scanner:
    def __init__(self, signatures: List[str] = None, min_size: int = 1):
        self.signatures = signatures or load_signatures()
        self.min_size = min_size

    def scan_directory(self, directory: Path, skip_hidden: bool = True) -> ScanReport:
        start = time.perf_counter()
        scanned_files = 0
        detections: List[Detection] = []

        for root, _, files in os.walk(directory):
            root_path = Path(root)
            if skip_hidden and root_path.name.startswith("."):
                continue

            if DEFAULT_QUARANTINE_DIR in root_path.parents or root_path == DEFAULT_QUARANTINE_DIR:
                continue

            for filename in files:
                file_path = root_path / filename
                if skip_hidden and file_path.name.startswith("."):
                    continue
                scanned_files += 1
                detection = self.scan_file(file_path)
                if detection:
                    detections.append(detection)

        duration = time.perf_counter() - start
        return ScanReport(scanned_files=scanned_files, detections=detections, duration_seconds=duration)

    def scan_file(self, path: Path) -> Optional[Detection]:
        if not path.is_file() or path.stat().st_size < self.min_size:
            return None

        signatures = []
        heuristics = self._inspect_heuristics(path)

        try:
            content = path.read_bytes()
        except OSError:
            return None

        for signature in self.signatures:
            if signature.encode("utf-8") in content:
                signatures.append(signature)

        if signatures or heuristics:
            return Detection(path=path, signatures=signatures, heuristics=heuristics)
        return None

    def _inspect_heuristics(self, path: Path) -> List[str]:
        heuristics: List[str] = []
        suffix = path.suffix.lower()
        if suffix in SUSPICIOUS_EXTENSIONS:
            heuristics.append(f"Extensión sospechosa: {suffix}")
        elif suffix not in KNOWN_SAFE_EXTENSIONS and suffix:
            heuristics.append(f"Extensión no habitual: {suffix}")

        try:
            size = path.stat().st_size
            if size == 0:
                heuristics.append("Archivo vacío")
            elif size > 20_000_000:
                heuristics.append("Archivo grande que merece revisión")
        except OSError:
            pass

        if path.name.lower().startswith("install"):
            heuristics.append("Nombre de archivo con patrón instalador")

        return heuristics
