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
import logging
import traceback
from datetime import datetime

# Set up logging
log_file = f"dbd_esp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Also log to console if available
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

from .memory import MemoryReader
from .entity import EntityManager
from .overlay import Overlay
from .process_utils import ProcessHider, ProcessMonitor
from .status import StatusDisplay

def log_exception(e: Exception):
    """Log an exception with full traceback"""
    logging.error(f"Exception occurred: {str(e)}")
    logging.error(traceback.format_exc())

class ESPHack:
    def __init__(self):
        self.memory: Optional[MemoryReader] = None
        self.entity_manager: Optional[EntityManager] = None
        self.overlay: Optional[Overlay] = None
        self.process_hider: Optional[ProcessHider] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.status_display: Optional[StatusDisplay] = None
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
            print("[*] Make sure Dead by Daylight is running")
            print("[*] Game must be in windowed or borderless mode")
            print("[*] Press CTRL+C to exit...")
            
            try:
                if not self.memory.attach():
                    print("\n[-] Failed to attach to game process")
                    print("[!] Common issues:")
                    print("    1. Game is not running")
                    print("    2. Game is running but not fully loaded")
                    print("    3. Game is in fullscreen mode")
                    print("    4. ESP needs administrator privileges")
                    print("\n[*] Press any key to exit...")
                    input()
                    return False
                    
                print("[+] Successfully attached to game process")
            except KeyboardInterrupt:
                print("\n[*] ESP stopped by user")
                return False
            except Exception as e:
                print(f"\n[-] Error attaching to game: {e}")
                print("[!] This could be due to:")
                print("    1. Anti-cheat blocking access")
                print("    2. Game version mismatch")
                print("    3. Insufficient permissions")
                print("\n[*] Press any key to exit...")
                input()
                return False
            
            # Initialize entity manager with batching
            print("[*] Initializing entity manager...")
            self.entity_manager = EntityManager(self.memory)
            
            # Initialize status display
            print("[*] Initializing status display...")
            self.status_display = StatusDisplay()
            self.status_display.start()
            
            # Create overlay last
            print("[*] Creating overlay...")
            self.overlay = Overlay()
            
            # Update initial status
            if self.status_display:
                self.status_display.update_entities(self.entity_manager.entities)
            
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
                
                # Check if ESP is enabled
                if self.status_display and not self.status_display.settings['esp_enabled']:
                    time.sleep(0.1)
                    continue

                # Update entities in batches
                self.memory.process_batch_reads()  # Process any queued reads
                self.entity_manager.update()
                
                # Update status display
                if self.status_display:
                    self.status_display.update_entities(self.entity_manager.entities)
                    self.status_display.settings['refresh_rate'] = int(1.0 / frame_time)
                
                last_update = time.time()
                update_count += 1
                
                # Clear memory cache periodically
                if update_count % 100 == 0:
                    self.memory.cache.clear()

                # Adjust delay based on performance mode
                if self.status_display and self.status_display.settings['performance_mode']:
                    time.sleep(0.1)  # 10 FPS in performance mode
                
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
                    
                # Check if ESP is enabled
                if self.status_display and not self.status_display.settings['esp_enabled']:
                    time.sleep(0.1)
                    continue

                # Apply status display settings to overlay
                if self.status_display:
                    self.overlay.box_thickness = self.status_display.settings['box_thickness']
                    self.overlay.text_size = self.status_display.settings['text_size']
                    self.overlay.show_items = self.status_display.settings['show_items']
                    self.overlay.show_health = self.status_display.settings['show_health']
                    self.overlay.show_distance = self.status_display.settings['show_distance']
                    self.overlay.killer_color = self.status_display.settings['killer_color']
                    self.overlay.survivor_color = self.status_display.settings['survivor_color']
                    self.overlay.injured_color = self.status_display.settings['injured_color']
                    self.overlay.dying_color = self.status_display.settings['dying_color']
                    self.overlay.carried_color = self.status_display.settings['carried_color']

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
        print("    - F1: Toggle ESP On/Off")
        print("    - F2: Toggle Items Display")
        print("    - F3: Toggle Health Display")
        print("    - F4: Toggle Distance Display")
        print("    - F5: Toggle Performance Mode")
        print("    - F6: Cycle Killer Color")
        print("    - F7/F8: Adjust Box Thickness")
        print("    - F9/F10: Adjust Text Size")
        print("\n[*] Status Display:")
        print("    - Check dbd_status.txt for real-time info")
        print("    - Shows active players and settings")
        print("    - Updates automatically")
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
            if self.status_display:
                self.status_display.stop()
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
    try:
        # Check for admin rights
        if not is_admin():
            print("[-] This script requires administrator privileges")
            print("[!] Please run as administrator")
            print("\n[*] Press any key to exit...")
            input()
            return
            
        # Create mutex to prevent multiple instances
        mutex = win32event.CreateMutex(None, 1, "DBD_ESP_MUTEX")
        if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            print("[-] Another instance is already running")
            print("[!] Close the other ESP instance first")
            print("\n[*] Press any key to exit...")
            input()
            return
            
        try:
            # Start ESP
            esp = ESPHack()
            esp.run()
        finally:
            win32event.ReleaseMutex(mutex)
            
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        print("[!] Please report this error")
        print("[*] Check error.log for details")
        print("\n[*] Press any key to exit...")
        input()

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
