#!/usr/bin/env python3
"""
SecureGuard Antivirus - prototipo educativo de escaneo de archivos.
Este script demuestra un scanner simple basado en firmas.
No es un antivirus real.
"""

import os
import shutil
import sys
from pathlib import Path

SIGNATURE_FILE = Path(__file__).with_name("signatures.txt")
QUARANTINE_DIR = Path(__file__).with_name("quarantine")

def load_signatures():
    signatures = []
    if not SIGNATURE_FILE.exists():
        return signatures

    for line in SIGNATURE_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        signatures.append(line.encode("utf-8"))
    return signatures


def scan_file(path, signatures):
    if not signatures:
        return []

    try:
        data = path.read_bytes()
    except Exception:
        return []

    hits = []
    for sig in signatures:
        if sig in data:
            hits.append(sig.decode("utf-8", errors="ignore"))
    return hits


def scan_directory(directory):
    signatures = load_signatures()
    if not signatures:
        print("[!] No se encontraron firmas en signatures.txt.")
        return 1

    if not directory.exists() or not directory.is_dir():
        print(f"[!] La ruta especificada no existe o no es un directorio: {directory}")
        return 1

    QUARANTINE_DIR.mkdir(exist_ok=True)
    total_files = 0
    detected = 0
    detections = []

    print(f"Iniciando escaneo en: {directory.resolve()}")
    print(f"Firmas cargadas: {len(signatures)}")

    for root, _, files in os.walk(directory):
        root_path = Path(root)
        if QUARANTINE_DIR in root_path.parents or root_path == QUARANTINE_DIR:
            continue

        for filename in files:
            total_files += 1
            file_path = root_path / filename
            matches = scan_file(file_path, signatures)
            if matches:
                detected += 1
                detections.append((file_path, matches))
                quarantine_file(file_path)
                print(f"[!] Amenaza detectada: {file_path}")
                for sig in matches:
                    print(f"    - Firma encontrada: {sig}")

    print("\nEscaneo finalizado")
    print(f"Archivos analizados: {total_files}")
    print(f"Amenazas detectadas: {detected}")
    if detected:
        print(f"Archivos copiados a cuarentena: {QUARANTINE_DIR.resolve()}")
    else:
        print("No se detectaron amenazas en esta prueba.")

    return 0


def quarantine_file(path):
    try:
        destination = QUARANTINE_DIR / path.name
        shutil.copy2(path, destination)
    except Exception:
        pass


def print_help():
    print("SecureGuard Antivirus - Prototipo educativo")
    print("Uso:")
    print("  python antivirus_demo.py scan <directorio>")
    print("  python antivirus_demo.py help")
    print("")
    print("Ejemplo:")
    print("  python antivirus_demo.py scan .")
    print("")
    print("Este script busca cadenas definidas en signatures.txt dentro de los archivos.")
    print("No es un antivirus real; es un ejemplo de identificación de firmas.")


if __name__ == "__main__":
    import os

    if len(sys.argv) < 2 or sys.argv[1] in {"help", "-h", "--help"}:
        print_help()
        sys.exit(0)

    command = sys.argv[1].lower()
    if command == "scan":
        if len(sys.argv) != 3:
            print("[!] Uso: python antivirus_demo.py scan <directorio>")
            sys.exit(1)
        target_dir = Path(sys.argv[2])
        sys.exit(scan_directory(target_dir))

    print_help()
    sys.exit(1)
