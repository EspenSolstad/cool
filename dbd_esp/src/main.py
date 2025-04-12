import time
import random
import sys
import threading
from typing import Optional
import ctypes
import os

from .memory import MemoryReader
from .entity import EntityManager
from .overlay import Overlay

class ESPHack:
    def __init__(self):
        self.memory: Optional[MemoryReader] = None
        self.entity_manager: Optional[EntityManager] = None
        self.overlay: Optional[Overlay] = None
        self.running = False
        
        # Randomize update intervals to avoid detection
        self.min_update_delay = 0.016  # ~60 FPS max
        self.max_update_delay = 0.033  # ~30 FPS min
        
    def initialize(self) -> bool:
        """Initialize all components"""
        try:
            print("[*] Initializing memory reader...")
            self.memory = MemoryReader()
            if not self.memory.attach():
                print("[-] Failed to attach to game process")
                return False
                
            print("[+] Successfully attached to game process")
            
            print("[*] Initializing entity manager...")
            self.entity_manager = EntityManager(self.memory)
            
            print("[*] Creating overlay...")
            self.overlay = Overlay()
            
            return True
            
        except Exception as e:
            print(f"[-] Initialization failed: {e}")
            return False
            
    def update_thread(self):
        """Thread for updating entity information"""
        while self.running:
            try:
                # Random delay between updates
                time.sleep(random.uniform(self.min_update_delay, self.max_update_delay))
                
                # Update entities
                self.entity_manager.update()
                
            except Exception as e:
                print(f"[-] Update error: {e}")
                time.sleep(1)  # Avoid spam on error
                
    def render_thread(self):
        """Thread for rendering the overlay"""
        while self.running:
            try:
                if not self.overlay.handle_events():
                    self.running = False
                    break
                    
                # Render entities
                self.overlay.render(self.entity_manager.entities)
                
                # Small delay to avoid excessive CPU usage
                time.sleep(0.016)  # ~60 FPS
                
            except Exception as e:
                print(f"[-] Render error: {e}")
                time.sleep(1)
                
    def run(self):
        """Main run loop"""
        if not self.initialize():
            return
            
        print("\n[+] ESP Hack initialized successfully!")
        print("[*] Controls:")
        print("    - ESC: Exit")
        print("\n[!] Remember:")
        print("    - Keep this window minimized")
        print("    - The overlay will appear over the game")
        print("    - Use at your own risk!")
        print("\n[*] Starting ESP...\n")
        
        self.running = True
        
        # Start update thread
        update_thread = threading.Thread(target=self.update_thread)
        update_thread.daemon = True
        update_thread.start()
        
        # Start render thread
        render_thread = threading.Thread(target=self.render_thread)
        render_thread.daemon = True
        render_thread.start()
        
        # Main thread just waits for exit
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            
        # Cleanup
        if self.overlay:
            self.overlay.cleanup()
            
def is_admin():
    """Check if script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    # Check for admin rights
    if not is_admin():
        print("[-] This script requires administrator privileges")
        print("[!] Please run as administrator")
        return
        
    # Start ESP
    esp = ESPHack()
    esp.run()

if __name__ == "__main__":
    # Add random delay on startup to avoid detection patterns
    time.sleep(random.uniform(1.0, 3.0))
    
    # Randomize process name
    if hasattr(sys, 'frozen'):
        # If compiled with PyInstaller, rename the process
        ctypes.windll.kernel32.SetConsoleTitleW(f"Windows System Service {random.randint(1000,9999)}")
    
    main()
