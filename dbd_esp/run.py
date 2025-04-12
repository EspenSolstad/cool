import sys
import os
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    # Check for admin rights
    if not is_admin():
        print("[-] This script requires administrator privileges")
        print("[!] Please run as administrator")
        sys.exit(1)

    # Add the package directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Import and run the ESP
    from src.main import main
    main()
