from pathlib import Path
import os
import shutil
import logging
from datetime import datetime


LOG_FILE = "scan_folder.log"
REPORT_FILE = "scan_report.txt"


def setup_logging() -> logging.Logger:
    """
    Logs to BOTH:
      - console (INFO+)
      - file (DEBUG+)
    """
    logger = logging.getLogger("folder_scanner")
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if you re-run in the same session (rare, but good practice)
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    # File handler
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger


def scan_folder(folder: Path, recursive: bool, logger: logging.Logger) -> dict[str, list[Path]]:
    """
    Returns: {".txt": [Path(...)], "<no_extension>": [...]}
    """
    results: dict[str, list[Path]] = {}

    try:
        if recursive:
            items = (p for p in folder.rglob("*") if p.is_file())
        else:
            items = (p for p in folder.iterdir() if p.is_file())

        for file_path in items:
            ext = file_path.suffix.lower() if file_path.suffix else "<no_extension>"
            results.setdefault(ext, []).append(file_path)

        for ext in results:
            results[ext].sort(key=lambda p: p.name.lower())

        logger.info("Scan complete. Found %d file types.", len(results))
        logger.debug("Extensions found: %s", list(results.keys()))
        return results

    except PermissionError as e:
        logger.error("Permission denied scanning folder: %s | %s", folder, e)
        return results  # empty
    except FileNotFoundError as e:
        logger.error("Folder disappeared during scan: %s | %s", folder, e)
        return results
    except Exception as e:
        logger.exception("Unexpected error during scan: %s", e)
        return results


def format_report(folder: Path, grouped: dict[str, list[Path]], recursive: bool) -> str:
    total_files = sum(len(files) for files in grouped.values())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("=== Folder Scan Report ===")
    lines.append(f"Timestamp: {timestamp}")
    lines.append(f"Folder: {folder}")
    lines.append(f"Recursive: {recursive}")
    lines.append(f"Current Working Directory: {Path(os.getcwd())}")
    lines.append(f"Total files found: {total_files}")
    lines.append("")

    ext_sorted = sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    for ext, files in ext_sorted:
        lines.append(f"[{ext}] ({len(files)} files)")
        for f in files:
            lines.append(f"  - {f.name}")
        lines.append("")

    return "\n".join(lines)


def write_report(report_path: Path, content: str, logger: logging.Logger) -> bool:
    try:
        report_path.write_text(content, encoding="utf-8")
        logger.info("Report written: %s", report_path)
        return True
    except PermissionError as e:
        logger.error("Permission denied writing report: %s | %s",
                     report_path, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error writing report: %s", e)
        return False


def optional_copy_report(report_path: Path, copy_to: Path | None, logger: logging.Logger) -> None:
    if copy_to is None:
        return

    try:
        copy_to.mkdir(parents=True, exist_ok=True)
        destination = copy_to / report_path.name
        shutil.copy2(report_path, destination)
        logger.info("Report copied to: %s", destination)
    except PermissionError as e:
        logger.error("Permission denied copying report to %s | %s", copy_to, e)
    except Exception as e:
        logger.exception("Unexpected error copying report: %s", e)


def get_folder_from_user(logger: logging.Logger) -> tuple[Path, bool]:
    """
    Handles missing folders gracefully:
      - prompts for folder
      - validates existence
      - falls back to current directory if blank
    """
    folder_input = input(
        "Enter folder path to scan (leave blank for current folder): ").strip()
    folder = Path(folder_input) if folder_input else Path.cwd()

    if not folder.exists():
        logger.warning("Folder does not exist: %s", folder)
        print(f"⚠️ Folder not found: {folder}")
        print("Tip: double-check the path and try again.\n")
        # Gracefully fall back to current directory
        folder = Path.cwd()
        logger.info("Falling back to current directory: %s", folder)

    if not folder.is_dir():
        logger.warning("Path is not a directory: %s", folder)
        print(
            f"⚠️ That path is not a folder. Using current folder instead: {Path.cwd()}\n")
        folder = Path.cwd()

    recursive_choice = input("Recursive scan? (y/n): ").strip().lower()
    recursive = (recursive_choice == "y")
    return folder, recursive


def main():
    logger = setup_logging()
    logger.info("=== Script started ===")

    try:
        folder, recursive = get_folder_from_user(logger)

        logger.info("Scanning folder: %s | recursive=%s", folder, recursive)
        grouped = scan_folder(folder, recursive=recursive, logger=logger)

        report_text = format_report(folder, grouped, recursive=recursive)
        report_path = Path.cwd() / REPORT_FILE

        if write_report(report_path, report_text, logger):
            print(f"\n✅ Report written to: {report_path}")
        else:
            print("\n❌ Could not write the report. Check scan_folder.log for details.")

        copy_choice = input(
            "Copy report to another folder? (y/n): ").strip().lower()
        if copy_choice == "y":
            dest_input = input("Enter destination folder path: ").strip()
            optional_copy_report(report_path, Path(dest_input), logger)

        logger.info("=== Script finished successfully ===")

    except KeyboardInterrupt:
        logger.warning("User cancelled the script (KeyboardInterrupt).")
        print("\nCancelled.")
    except Exception as e:
        logger.exception("Fatal error in main: %s", e)
        print("\n❌ Fatal error. Check scan_folder.log for details.")


if __name__ == "__main__":
    main()
