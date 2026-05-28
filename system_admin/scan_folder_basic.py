from pathlib import Path
import os
import shutil
from datetime import datetime


def scan_folder(folder: Path, recursive: bool = False) -> dict:
    """ 

    Returns a dictionary:
    {.txt": [Path(...), Path(...)], ".py": [...], "<no_extension>": [...]}
    """
    results: dict[str, list[Path]] = {}

    if recursive:
        items = (p for p in folder.rglob("*") if p.is_file())
    else:
        items = (p for p in folder.iterdir() if p.is_file())

    for file_path in items:
        ext = file_path.suffix.lower() if file_path.suffix else "<no_extension>"
        results.setdefault(ext, []).append(file_path)

    # Sort file lists for neat output
    for ext in results:
        results[ext].sort(key=lambda p: p.name.lower())

    return results


def format_report(folder: Path, grouped: dict, recursive: bool) -> str:
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

    # Extensions sorted by count desc, then name
    ext_sorted = sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    for ext, files in ext_sorted:
        lines.append(f"[{ext}] ({len(files)} files)")
        for f in files:
            lines.append(f"  - {f.name}")
        lines.append("")  # Blank line after each extension group

    return "\n".join(lines)


def write_report(output_path: Path, report: str) -> None:
    output_path.write_text(report, encoding="utf-8")


def optional_copy_report(report_path: Path, copy_to: Path | None) -> None:
    """
    Demonstrate shutil usage: optionally copy the report to another folder.
    """
    if copy_to is None:
        return

    copy_to.mkdir(parents=True, exist_ok=True)
    destination = copy_to / report_path.name
    shutil.copy2(report_path, destination)


def main():
    print("Files, Paths, and OS Automation\n")

    folder_input = input(
        "Enter the folder to scan (default: current directory): ").strip()
    folder = Path(folder_input) if folder_input else Path.cwd()

    if not folder.exists() or not folder.is_dir():
        print(f"Error: '{folder}' is not a valid directory.")
        return

    recursive_choice = input(
        "Scan recursively? (y/n, default: n): ").strip().lower()
    recursive = recursive_choice == 'y'

    grouped_files = scan_folder(folder, recursive=recursive)
    report_text = format_report(folder, grouped_files, recursive)

    report_path = Path.cwd() / "scan_report.txt"
    write_report(report_path, report_text)

    print(f"\nReport written to: {report_path}")

    # OPtional Shutil Demo
    copy_choice = input(
        "Copy report to another folder? (y/n, default: n): ").strip().lower()
    if copy_choice == 'y':
        copy_folder_input = input(
            "Enter the destination folder for the report copy: ").strip()
        copy_folder = Path(copy_folder_input)
        optional_copy_report(report_path, copy_folder)
        print(f"Report copied to: {copy_folder / report_path.name}")
    else:
        print("Report copy skipped.")


if __name__ == "__main__":
    main()
