from multiprocessing.util import info
import os
import platform
import getpass


def get_system_info():
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "username": getpass.getuser(),
        "current directory": os.getcwd()
    }
    return info


def print_system_info(info):
    print("\n=== System Information ===")
    for key, value in info.items():
        print(f"{key}: {value}")
        print("==========================\n")


def main():
    system_info = get_system_info()
    print_system_info(system_info)


if __name__ == "__main__":
    main()
