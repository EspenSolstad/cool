import win32api
import win32con
import win32process
import win32security
import win32service
import win32serviceutil
import win32event
import win32ts
import psutil
import ctypes
import time
import random
from typing import Optional, List, Tuple
import os

class ProcessHider:
    def __init__(self):
        self.hidden = False
        self.original_name = None
        self.spoofed_names = [
            "RuntimeBroker.exe",
            "sihost.exe",
            "SecurityHealthService.exe",
            "SearchApp.exe",
            "SystemSettings.exe"
        ]
        
    def hide_process(self) -> bool:
        """Hide the current process by manipulating PEB and process name"""
        try:
            # Get current process handle
            current_process = win32api.GetCurrentProcess()
            current_handle = current_process.handle if hasattr(current_process, 'handle') else current_process
            
            # Save original name
            if not self.original_name:
                self.original_name = win32process.GetModuleFileNameEx(current_process, 0)
            
            # Choose random system process name
            fake_name = random.choice(self.spoofed_names)
            
            # Get process basic information
            process_basic_info = ctypes.c_void_p()
            process_basic_info_size = ctypes.sizeof(process_basic_info)
            status = ctypes.windll.ntdll.NtQueryInformationProcess(
                current_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(process_basic_info),
                process_basic_info_size,
                None
            )
            
            if status != 0:
                print(f"Failed to query basic process information: {status}")
                return False
                
            # Get PEB address
            peb = ctypes.c_void_p.from_buffer(process_basic_info).value
            if not peb:
                print("Failed to get PEB address")
                return False
            
            # Modify process parameters
            params = ctypes.c_void_p()
            status = ctypes.windll.ntdll.NtQueryInformationProcess(
                current_handle,
                0x1F,  # ProcessImageFileName
                ctypes.byref(params),
                ctypes.sizeof(params),
                None
            )
            
            if status != 0:
                print(f"Failed to query process parameters: {status}")
                return False
                
            if not params.value:
                print("Failed to get process parameters")
                return False
                
            # Write fake name
            fake_name_buffer = ctypes.create_unicode_buffer(fake_name)
            result = ctypes.windll.kernel32.WriteProcessMemory(
                current_handle,
                params.value,
                fake_name_buffer,
                len(fake_name) * 2,
                None
            )
            
            if not result:
                print(f"Failed to write process memory: {ctypes.get_last_error()}")
                return False
            
            self.hidden = True
            return True
            
        except Exception as e:
            print(f"Failed to hide process: {e}")
            return False
            
    def unhide_process(self) -> bool:
        """Restore original process name"""
        if not self.hidden or not self.original_name:
            return False
            
        try:
            # Get current process handle
            current_process = win32api.GetCurrentProcess()
            current_handle = current_process.handle if hasattr(current_process, 'handle') else current_process
            
            # Restore original name
            original_buffer = ctypes.create_unicode_buffer(self.original_name)
            params = ctypes.c_void_p()
            status = ctypes.windll.ntdll.NtQueryInformationProcess(
                current_handle,
                0x1F,
                ctypes.byref(params),
                ctypes.sizeof(params),
                None
            )
            
            if status != 0:
                print(f"Failed to query process information: {status}")
                return False
                
            if not params.value:
                print("Failed to get process parameters")
                return False
                
            result = ctypes.windll.kernel32.WriteProcessMemory(
                current_handle,
                params.value,
                original_buffer,
                len(self.original_name) * 2,
                None
            )
            
            if not result:
                print(f"Failed to write process memory: {ctypes.get_last_error()}")
                return False
            
            self.hidden = False
            return True
            
        except Exception as e:
            print(f"Failed to unhide process: {e}")
            return False

class ProcessMonitor:
    def __init__(self):
        self.target_process = "DeadByDaylight-Win64-Shipping.exe"
        self.steam_process = "steam.exe"
        self._callback = None
        
    def set_callback(self, callback):
        """Set callback for when target process is found"""
        self._callback = callback
        
    def wait_for_steam(self) -> bool:
        """Wait for Steam to fully initialize"""
        try:
            print("[*] Looking for Steam process...")
            dots = 0
            while True:
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] == self.steam_process:
                        print("[+] Found Steam!")
                        print("[*] Waiting for Steam to initialize...")
                        # Wait a bit more for Steam to fully initialize
                        time.sleep(random.uniform(2.0, 4.0))
                        return True
                        
                # Show waiting animation
                print(f"\r[*] Waiting for Steam{'.' * dots + ' ' * (3-dots)}", end='')
                dots = (dots + 1) % 4
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\n[*] Search cancelled by user")
            return False
        except Exception as e:
            print(f"\n[-] Error searching for Steam: {e}")
            return False
            
    def wait_for_game(self) -> Optional[int]:
        """Wait for game process to start and return its PID"""
        try:
            print("[*] Looking for Dead by Daylight process...")
            dots = 0
            while True:
                for proc in psutil.process_iter(['name', 'pid']):
                    if proc.info['name'] == self.target_process:
                        print("[+] Found game process!")
                        print("[*] Waiting for game to initialize...")
                        # Small delay to let process initialize
                        time.sleep(random.uniform(1.0, 2.0))
                        return proc.info['pid']
                        
                # Show waiting animation
                print(f"\r[*] Waiting for game{'.' * dots + ' ' * (3-dots)}", end='')
                dots = (dots + 1) % 4
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\n[*] Search cancelled by user")
            return None
        except Exception as e:
            print(f"\n[-] Error searching for game: {e}")
            return None
            
    def monitor_process_start(self):
        """Monitor for process start in a separate thread"""
        import threading
        
        def _monitor():
            while True:
                pid = self.wait_for_game()
                if pid and self._callback:
                    self._callback(pid)
                time.sleep(0.1)
                
        monitor_thread = threading.Thread(target=_monitor, daemon=True)
        monitor_thread.start()
        
    @staticmethod
    def suspend_threads(pid: int, exclude_main: bool = True) -> List[int]:
        """Suspend all threads in a process except main thread if specified"""
        suspended = []
        try:
            process = psutil.Process(pid)
            threads = process.threads()
            
            main_tid = threads[0].id if exclude_main and threads else None
            
            for thread in threads:
                if thread.id == main_tid:
                    continue
                    
                thread_handle = win32api.OpenThread(
                    win32con.THREAD_SUSPEND_RESUME,
                    False,
                    thread.id
                )
                
                win32process.SuspendThread(thread_handle)
                suspended.append(thread.id)
                win32api.CloseHandle(thread_handle)
                
            return suspended
            
        except Exception as e:
            print(f"Failed to suspend threads: {e}")
            return suspended
            
    @staticmethod
    def resume_threads(pid: int, thread_ids: List[int]):
        """Resume previously suspended threads"""
        try:
            for tid in thread_ids:
                thread_handle = win32api.OpenThread(
                    win32con.THREAD_SUSPEND_RESUME,
                    False,
                    tid
                )
                
                win32process.ResumeThread(thread_handle)
                win32api.CloseHandle(thread_handle)
                
        except Exception as e:
            print(f"Failed to resume threads: {e}")
