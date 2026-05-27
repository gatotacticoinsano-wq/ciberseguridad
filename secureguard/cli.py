import argparse
import sys
from pathlib import Path

from secureguard.config import DEFAULT_QUARANTINE_DIR, LOG_FILE, normalize_path, load_signatures
from secureguard.quarantine import QuarantineManager
from secureguard.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secureguard",
        description="SecureGuard Antivirus - prototipo de escaneo de firmas y cuarentena.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Escanea un directorio en busca de amenazas.")
    scan_parser.add_argument("path", nargs="?", default=".", help="Directorio de destino para el escaneo.")
    scan_parser.add_argument("--quarantine", default=str(DEFAULT_QUARANTINE_DIR), help="Carpeta de cuarentena.")
    scan_parser.add_argument("--report", default="scan-report.txt", help="Archivo de informe de resultados.")
    scan_parser.add_argument("--skip-hidden", action="store_true", help="Omitir archivos y carpetas ocultos.")
    scan_parser.add_argument("--verbose", action="store_true", help="Mostrar detalles de cada detección.")

    subparsers.add_parser("signatures", help="Muestra las firmas de detección cargadas.")
    subparsers.add_parser("version", help="Muestra la versión del proyecto.")

    return parser


def format_detection(detection):
    lines = [f"* {detection.path}"]
    if detection.signatures:
        lines.append("  - Firmas: " + ", ".join(detection.signatures))
    if detection.heuristics:
        lines.append("  - Heurísticas: " + ", ".join(detection.heuristics))
    return "\n".join(lines)


def save_report(report_path: Path, scan_report, quarantined_paths):
    with report_path.open("w", encoding="utf-8") as handle:
        handle.write("SecureGuard Antivirus - Informe de escaneo\n")
        handle.write(f"Escaneo completado: {scan_report.scanned_files} archivos analizados\n")
        handle.write(f"Amenazas detectadas: {len(scan_report.detections)}\n")
        handle.write(f"Duración: {scan_report.duration_seconds:.2f} segundos\n\n")
        if scan_report.detections:
            handle.write("Detecciones:\n")
            for detection in scan_report.detections:
                handle.write(format_detection(detection) + "\n\n")
        if quarantined_paths:
            handle.write("Archivos en cuarentena:\n")
            for path in quarantined_paths:
                handle.write(f"- {path}\n")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        from secureguard import __version__
        print(f"SecureGuard Antivirus {__version__}")
        return 0

    if args.command == "signatures":
        signatures = load_signatures()
        if not signatures:
            print("No hay firmas cargadas. Agrega firmas en signatures.txt.")
            return 0
        print("Firmas cargadas:")
        for signature in signatures:
            print(f"- {signature}")
        return 0

    if args.command == "scan":
        target = normalize_path(args.path)
        if not target.exists():
            print(f"[!] El directorio no existe: {target}")
            return 1

        scanner = Scanner()
        quarantine_manager = QuarantineManager(Path(args.quarantine))

        print(f"Iniciando escaneo en: {target}")
        print(f"Cuarentena: {quarantine_manager.quarantine_dir}")
        scan_report = scanner.scan_directory(target, skip_hidden=args.skip_hidden)

        quarantined_paths = []
        for detection in scan_report.detections:
            path = quarantine_manager.quarantine(detection.path)
            if path:
                quarantined_paths.append(path)

        print("\nEscaneo finalizado")
        print(f"Archivos analizados: {scan_report.scanned_files}")
        print(f"Amenazas detectadas: {len(scan_report.detections)}")
        print(f"Informe generado: {args.report}")
        if quarantined_paths:
            print(f"Archivos enviados a cuarentena: {len(quarantined_paths)}")

        if args.verbose and scan_report.detections:
            for detection in scan_report.detections:
                print(format_detection(detection))
                print()

        save_report(Path(args.report), scan_report, quarantined_paths)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
