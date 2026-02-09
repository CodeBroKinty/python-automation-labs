"""
system_info.py
Collects and displays basic system information for diagnostic purposes.
"""

import os
import platform
import getpass


def get_system_info() -> dict[str, str]:
    """
    Collect basic system information.

    Returns:
        dict: System information including OS, version, username, and current directory
    """
    return {
        "OS": platform.system(),
        "OS Version": platform.release(),
        "Username": getpass.getuser(),
        "Current Directory": os.getcwd()
    }


def print_system_info(info: dict[str, str]) -> None:
    """
    Print system information in a formatted display.

    Args:
        info: Dictionary containing system information
    """
    print("\n=== SYSTEM INFORMATION ===")
    for key, value in info.items():
        print(f"{key}: {value}")
    print("==========================\n")


def main() -> None:
    """Main execution function."""
    system_info = get_system_info()
    print_system_info(system_info)


if __name__ == "__main__":
    main()
