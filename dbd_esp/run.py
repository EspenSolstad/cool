import os
import sys
import traceback
import ctypes
import time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main_wrapper():
    try:
        # Add the src directory to Python path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, current_dir)

        # Import and run the ESP
        from src.main import main
        main()
    except Exception as e:
        error_msg = f"Fatal error: {str(e)}\n\n{traceback.format_exc()}"
        
        # Try to write to a log file
        try:
            with open("error.log", "w") as f:
                f.write(error_msg)
        except:
            pass
            
        # Show error in message box
        try:
            ctypes.windll.user32.MessageBoxW(0, error_msg, "DBD ESP Error", 0x10)
        except:
            # If message box fails, try to keep console open
            print(error_msg)
            time.sleep(30)

if __name__ == "__main__":
    # Check for admin rights
    if not is_admin():
        try:
            ctypes.windll.user32.MessageBoxW(0, "Please run as administrator!", "DBD ESP", 0x10)
        except:
            print("Please run as administrator!")
        sys.exit(1)
        
    main_wrapper()
