import time
import random
import sys
import threading
from typing import Optional
import ctypes
import os
import win32event
import win32process
import win32con
import win32api

from .memory import MemoryReader
from .entity import EntityManager
from .overlay import Overlay
from .process_utils import ProcessHider, ProcessMonitor

class ESPHack:
    def __init__(self):
        self.memory: Optional[MemoryReader] = None
        self.entity_manager: Optional[EntityManager] = None
        self.overlay: Optional[Overlay] = None
        self.process_hider: Optional[ProcessHider] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.running = False
        
        # Performance tuning
        self.min_update_delay = 0.008  # ~120 FPS max
        self.max_update_delay = 0.016  # ~60 FPS min
        self.batch_update_size = 8  # Number of entities to update per batch
        
    def initialize(self) -> bool:
        """Initialize all components with improved stealth"""
        try:
            # Hide our process first
            print("[*] Hiding process...")
            self.process_hider = ProcessHider()
            if not self.process_hider.hide_process():
                print("[!] Warning: Failed to hide process")
            
            # Initialize process monitor
            print("[*] Initializing process monitor...")
            self.process_monitor = ProcessMonitor()
            
            # Initialize memory reader (which will wait for Steam/game)
            print("[*] Initializing memory reader...")
            self.memory = MemoryReader()
            
            # Set high process priority
            handle = win32api.GetCurrentProcess()
            win32process.SetPriorityClass(handle, win32process.HIGH_PRIORITY_CLASS)
            
            # Wait for game and attach
            print("[*] Waiting for game process...")
            if not self.memory.attach():
                print("[-] Failed to attach to game process")
                return False
                
            print("[+] Successfully attached to game process")
            
            # Initialize entity manager with batching
            print("[*] Initializing entity manager...")
            self.entity_manager = EntityManager(self.memory)
            
            # Create overlay last
            print("[*] Creating overlay...")
            self.overlay = Overlay()
            
            return True
            
        except Exception as e:
            print(f"[-] Initialization failed: {e}")
            return False
            
    def update_thread(self):
        """Thread for updating entity information with batching"""
        last_update = time.time()
        update_count = 0
        
        while self.running:
            try:
                current_time = time.time()
                frame_time = current_time - last_update
                
                # Dynamically adjust update rate based on performance
                if frame_time < self.min_update_delay:
                    time.sleep(self.min_update_delay - frame_time)
                elif frame_time > self.max_update_delay:
                    # We're running slow, increase batch size
                    self.batch_update_size = min(16, self.batch_update_size + 1)
                else:
                    # We're running well, try to decrease batch size
                    self.batch_update_size = max(4, self.batch_update_size - 1)
                
                # Update entities in batches
                self.memory.process_batch_reads()  # Process any queued reads
                self.entity_manager.update()
                
                last_update = time.time()
                update_count += 1
                
                # Clear memory cache periodically
                if update_count % 100 == 0:
                    self.memory.cache.clear()
                
            except Exception as e:
                print(f"[-] Update error: {e}")
                time.sleep(1)
                
    def render_thread(self):
        """Thread for rendering the overlay with vsync"""
        while self.running:
            try:
                if not self.overlay.handle_events():
                    self.running = False
                    break
                    
                # Render entities
                self.overlay.render(self.entity_manager.entities)
                
            except Exception as e:
                print(f"[-] Render error: {e}")
                time.sleep(1)
                
    def run(self):
        """Main run loop with improved error handling"""
        if not self.initialize():
            return
            
        print("\n[+] ESP Hack initialized successfully!")
        print("[*] Performance settings:")
        print(f"    - Update batch size: {self.batch_update_size}")
        print(f"    - Min update delay: {self.min_update_delay*1000:.1f}ms")
        print(f"    - Max update delay: {self.max_update_delay*1000:.1f}ms")
        print("\n[*] Controls:")
        print("    - ESC: Exit")
        print("\n[!] Remember:")
        print("    - Keep this window minimized")
        print("    - The overlay will appear over the game")
        print("    - Use at your own risk!")
        print("\n[*] Starting ESP...\n")
        
        self.running = True
        
        # Start update thread with high priority
        update_thread = threading.Thread(target=self.update_thread)
        update_thread.daemon = True
        update_thread.start()
        win32api.SetThreadPriority(update_thread.native_id, win32con.THREAD_PRIORITY_HIGHEST)
        
        # Start render thread with normal priority
        render_thread = threading.Thread(target=self.render_thread)
        render_thread.daemon = True
        render_thread.start()
        
        # Main thread monitors for problems
        try:
            while self.running:
                # Check if game process still exists
                if not self.memory.pm or not win32process.GetExitCodeProcess(self.memory.pm.process_handle) == win32con.STILL_ACTIVE:
                    print("[-] Game process ended")
                    self.running = False
                    break
                    
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.running = False
            
        finally:
            # Cleanup
            if self.overlay:
                self.overlay.cleanup()
            if self.process_hider:
                self.process_hider.unhide_process()
            
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
        
    # Create mutex to prevent multiple instances
    mutex = win32event.CreateMutex(None, 1, "DBD_ESP_MUTEX")
    if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        print("[-] Another instance is already running")
        return
        
    try:
        # Start ESP
        esp = ESPHack()
        esp.run()
    finally:
        win32event.ReleaseMutex(mutex)

if __name__ == "__main__":
    # Add random startup delay
    time.sleep(random.uniform(0.5, 1.5))
    
    # Set DLL directory to system32 to avoid DLL hijacking
    ctypes.windll.kernel32.SetDllDirectoryW(None)
    
    # If compiled, hide process name
    if hasattr(sys, 'frozen'):
        # Choose random system service name
        service_names = [
            "Windows Update Service",
            "Network Service Manager",
            "System Resource Monitor",
            "Hardware Event Manager",
            "Security Service Provider"
        ]
        ctypes.windll.kernel32.SetConsoleTitleW(f"{random.choice(service_names)} {random.randint(1000,9999)}")
    
    main()
