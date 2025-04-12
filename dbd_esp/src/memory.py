import time
import random
from typing import Optional, Tuple, List, Dict, Set
import psutil
from pymem import Pymem
from pymem.process import module_from_name
import numpy as np
from .process_utils import ProcessMonitor
from .offsets import Patterns, Engine

class MemoryCache:
    def __init__(self, max_size: int = 1024):
        self.cache: Dict[int, bytes] = {}
        self.access_times: Dict[int, float] = {}
        self.max_size = max_size
        
    def get(self, address: int, size: int) -> Optional[bytes]:
        """Get cached memory if available and not expired"""
        key = (address // 4096) * 4096  # Page-aligned key
        if key in self.cache:
            data = self.cache[key]
            if len(data) >= size:
                offset = address - key
                if offset + size <= len(data):
                    # Update access time
                    self.access_times[key] = time.time()
                    return data[offset:offset + size]
        return None
        
    def store(self, address: int, data: bytes):
        """Store memory in cache"""
        key = (address // 4096) * 4096
        
        # If cache is full, remove oldest entries
        while len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times.items(), key=lambda x: x[1])[0]
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
            
        self.cache[key] = data
        self.access_times[key] = time.time()
        
    def clear(self):
        """Clear the cache"""
        self.cache.clear()
        self.access_times.clear()

class MemoryReader:
    def __init__(self):
        self.pm: Optional[Pymem] = None
        self.base_address: int = 0
        self.process_name = "DeadByDaylight-Win64-Shipping.exe"
        self.cache = MemoryCache()
        self.process_monitor = ProcessMonitor()
        self.batch_reads: Dict[int, Set[int]] = {}  # Page -> set of addresses to read
        self.batch_size = 4096  # Read in 4KB chunks
        
    def attach(self) -> bool:
        """Attach to the DBD process with improved timing"""
        try:
            # Wait for Steam first
            if not self.process_monitor.wait_for_steam():
                print("[-] Steam not detected")
                print("[!] Make sure Steam is running")
                return False
                
            # Wait for game process
            pid = self.process_monitor.wait_for_game()
            if not pid:
                print("[-] Game process not found")
                print("[!] Make sure Dead by Daylight is running")
                print("[!] Game must be fully loaded")
                return False
                
            # Attach to process
            try:
                self.pm = Pymem(pid)
            except Exception as e:
                print("[-] Failed to attach to game process")
                print("[!] This could be due to:")
                print("    1. Game is in fullscreen mode")
                print("    2. Anti-cheat is blocking access")
                print("    3. ESP needs administrator privileges")
                print(f"[*] Error details: {e}")
                return False
                
            # Get game module
            module = module_from_name(self.pm.process_handle, self.process_name)
            if not module:
                print("[-] Failed to find game module directly")
                print("[*] Attempting pattern scan fallback...")
                # Try to find GWorld through pattern scanning
                print("[*] Attempting pattern scan with multiple signatures...")
                
                # Try each GWorld pattern
                patterns = [
                    ("Primary", Patterns.UWORLD),
                    ("Alt 1", Patterns.UWORLD_ALT1),
                    ("Alt 2", Patterns.UWORLD_ALT2)
                ]
                
                for pattern_name, pattern in patterns:
                    print(f"[*] Trying {pattern_name} pattern...")
                    base_addr = self.find_pattern(*pattern)
                    if base_addr:
                        print(f"\n[+] Found GWorld using {pattern_name} pattern!")
                        # Get module base from pattern address
                        self.base_address = base_addr & 0xFFFFFFFFFFF00000
                        print(f"[*] Base address: 0x{self.base_address:X}")
                        return True
                
                print("\n[-] All pattern scans failed")
                print("[!] The game may have updated")
                print("[!] ESP may need to be updated")
                return False
                
            self.base_address = module.lpBaseOfDll
            return True
            
        except Exception as e:
            print("[-] Unexpected error during attachment:")
            print(f"[!] {str(e)}")
            print("[*] Please report this error")
            return False
            
    def queue_read(self, address: int, size: int):
        """Queue a memory read for batch processing"""
        page_start = (address // self.batch_size) * self.batch_size
        if page_start not in self.batch_reads:
            self.batch_reads[page_start] = set()
        self.batch_reads[page_start].add(address)
        
    def process_batch_reads(self):
        """Process all queued reads in efficient batches"""
        if not self.batch_reads:
            return
            
        # Suspend other threads during batch read
        pid = self.pm.process_id
        suspended_threads = ProcessMonitor.suspend_threads(pid)
        
        try:
            for page_start, addresses in self.batch_reads.items():
                # Read entire page at once
                data = self.read_bytes_direct(page_start, self.batch_size)
                if data:
                    self.cache.store(page_start, data)
                    
        finally:
            # Resume threads
            ProcessMonitor.resume_threads(pid, suspended_threads)
            
        # Clear batch queue
        self.batch_reads.clear()
        
    def read_bytes_direct(self, address: int, size: int) -> bytes:
        """Direct memory read without caching or batching"""
        if not self.pm:
            return b''
            
        try:
            return self.pm.read_bytes(address, size)
        except:
            return b''
            
    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes with caching and batch optimization"""
        if not self.pm:
            return b''
            
        # Check cache first
        cached = self.cache.get(address, size)
        if cached:
            return cached
            
        # Queue read for batch processing if small
        if size <= 32:  # Only batch small reads
            self.queue_read(address, size)
            self.process_batch_reads()
            
            # Try cache again after batch processing
            cached = self.cache.get(address, size)
            if cached:
                return cached
                
        # Fall back to direct read
        return self.read_bytes_direct(address, size)
        
    def read_int(self, address: int) -> int:
        """Read 32-bit integer"""
        try:
            return int.from_bytes(self.read_bytes(address, 4), byteorder='little')
        except:
            return 0
            
    def read_long(self, address: int) -> int:
        """Read 64-bit integer"""
        try:
            return int.from_bytes(self.read_bytes(address, 8), byteorder='little')
        except:
            return 0
            
    def read_float(self, address: int) -> float:
        """Read 32-bit float"""
        try:
            return np.frombuffer(self.read_bytes(address, 4), dtype=np.float32)[0]
        except:
            return 0.0
            
    def read_vec3(self, address: int) -> Tuple[float, float, float]:
        """Read Vector3 (3 floats)"""
        try:
            data = np.frombuffer(self.read_bytes(address, 12), dtype=np.float32)
            return (data[0], data[1], data[2])
        except:
            return (0.0, 0.0, 0.0)
            
    def read_string(self, address: int, size: int = 32) -> str:
        """Read string with maximum size"""
        try:
            data = self.read_bytes(address, size)
            string = data.split(b'\x00')[0]
            return string.decode('utf-8')
        except:
            return ""
            
    def find_pattern(self, pattern: bytes, mask: str) -> int:
        """Find pattern with optimized scanning"""
        if not self.pm:
            return 0
            
        try:
            chunk_size = 0x10000  # Larger chunks for faster scanning
            current_addr = 0x10000  # Start after null page
            
            # Suspend threads during pattern scan
            pid = self.pm.process_id
            suspended_threads = ProcessMonitor.suspend_threads(pid)
            
            try:
                max_addr = 0x7FFFFFFF  # Scan up to 2GB of memory
                last_progress = 0
                
                while current_addr < max_addr:
                    # Show progress every 100MB
                    progress = (current_addr * 100) // max_addr
                    if progress > last_progress:
                        print(f"\r[*] Scanning memory: {progress}%", end='')
                        last_progress = progress
                        
                    try:
                        chunk = self.read_bytes_direct(current_addr, chunk_size)
                        if not chunk:
                            current_addr += chunk_size
                            continue
                        
                    for i in range(len(chunk)):
                        matched = True
                        for j in range(len(pattern)):
                            if i + j >= len(chunk):
                                matched = False
                                break
                            if mask[j] != '?' and pattern[j] != chunk[i + j]:
                                matched = False
                                break
                                
                        if matched:
                            return current_addr + i
                            
                    current_addr += chunk_size - len(pattern)
                    
            finally:
                # Resume threads
                ProcessMonitor.resume_threads(pid, suspended_threads)
                
        except Exception as e:
            print(f"Pattern scan failed: {e}")
            
        return 0
        
    def get_pointer_chain(self, base: int, offsets: List[int]) -> int:
        """Follow pointer chain with batch optimization"""
        if not self.pm:
            return 0
            
        addr = base
        try:
            # Queue all pointer reads
            addresses = [addr]
            for offset in offsets[:-1]:
                addr = self.read_long(addr)
                if addr == 0:
                    return 0
                addr += offset
                addresses.append(addr)
                
            # Process batch reads
            self.process_batch_reads()
            
            # Follow chain using cached values
            addr = base
            for offset in offsets:
                addr = self.read_long(addr)
                if addr == 0:
                    return 0
                addr += offset
                
            return addr
            
        except:
            return 0
