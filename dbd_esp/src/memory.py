import time
import random
import ctypes
import ctypes.wintypes as wintypes
from typing import Optional, Tuple, List, Dict, Set
import psutil
import numpy as np
from .process_utils import ProcessMonitor
from .offsets import Engine

# Windows constants
PROCESS_ALL_ACCESS = 0x1F0FFF
SE_DEBUG_PRIVILEGE = 20
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD)
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1)
    ]

def enable_debug_privilege():
    """Enable debug privilege for current process"""
    try:
        h_token = ctypes.c_void_p()
        if not ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)
        ):
            return False
            
        luid = LUID()
        if not ctypes.windll.advapi32.LookupPrivilegeValueW(
            None,
            "SeDebugPrivilege",
            ctypes.byref(luid)
        ):
            return False
            
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = 2  # SE_PRIVILEGE_ENABLED
        
        if not ctypes.windll.advapi32.AdjustTokenPrivileges(
            h_token,
            False,
            ctypes.byref(tp),
            ctypes.sizeof(tp),
            None,
            None
        ):
            return False
            
        return True
    except:
        return False

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
                
            # Get game module base
            module = module_from_name(self.pm.process_handle, self.process_name)
            if not module:
                print("[-] Failed to find game module")
                print("[!] Make sure the game is running")
                return False
                
            self.base_address = module.lpBaseOfDll
            print(f"[+] Found game module at: 0x{self.base_address:X}")
            
            # Verify GNames and GObjects
            gnames_ptr = self.base_address + Engine.GNames
            gobjects_ptr = self.base_address + Engine.GObjects
            
            if not self.read_long(gnames_ptr) or not self.read_long(gobjects_ptr):
                print("[-] Failed to read GNames/GObjects")
                print("[!] Game may have updated")
                return False
                
            print("[+] Successfully found game structures")
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
            
        for page_start, addresses in self.batch_reads.items():
            # Read entire page at once
            data = self.read_bytes_direct(page_start, self.batch_size)
            if data:
                self.cache.store(page_start, data)
                
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
            
    def read_short(self, address: int) -> int:
        """Read 16-bit integer"""
        try:
            return int.from_bytes(self.read_bytes(address, 2), byteorder='little')
        except:
            return 0
            
    def read_string(self, address: int, size: int = 32) -> str:
        """Read string with maximum size"""
        try:
            data = self.read_bytes(address, size)
            string = data.split(b'\x00')[0]
            return string.decode('utf-8')
        except:
            return ""
            
    def get_object_by_name(self, name: str) -> int:
        """Find object in GObjects array by name"""
        if not self.base_address:
            return 0
            
        try:
            # Get GObjects array
            gobjects = self.base_address + Engine.GObjects
            num_elements = self.read_int(gobjects + Engine.FChunkedFixedUObjectArray.NumElements)
            chunks = self.read_long(gobjects + Engine.FChunkedFixedUObjectArray.Chunks)
            
            if not chunks or num_elements <= 0:
                print("[-] Failed to read GObjects array")
                return 0
                
            print(f"[*] Searching through {num_elements} objects...")
            
            # Iterate through chunks
            chunk_size = Engine.FChunkedFixedUObjectArray.ChunkSize
            for i in range(0, num_elements, chunk_size):
                chunk_index = i // chunk_size
                chunk = self.read_long(chunks + chunk_index * 8)
                if not chunk:
                    continue
                    
                # Read objects in this chunk
                for j in range(min(chunk_size, num_elements - i)):
                    obj_ptr = self.read_long(chunk + j * 8)
                    if not obj_ptr:
                        continue
                        
                    # Get object name
                    name_index = self.read_int(obj_ptr + 0x18)  # FName.Index offset
                    obj_name = self.get_name(name_index)
                    
                    if obj_name == name:
                        print(f"[+] Found {name} at: 0x{obj_ptr:X}")
                        return obj_ptr
                        
            print(f"[-] Object {name} not found")
            return 0
            
        except Exception as e:
            print(f"[-] Failed to search objects: {e}")
            return 0
            
    def get_name(self, name_index: int) -> str:
        """Get string from FName pool"""
        try:
            if name_index == 0:
                return ""
                
            # Get name from pool
            name_pool = self.base_address + Engine.GNames
            block_id = name_index >> Engine.NameBlockOffsetBits
            block = self.read_long(name_pool + Engine.FNamePool.Blocks + block_id * 8)
            
            if not block:
                return ""
                
            entry = block + (name_index & ((1 << Engine.NameBlockOffsetBits) - 1)) * 2
            length = self.read_short(entry)
            
            if length <= 0:
                return ""
                
            name_data = self.read_bytes(entry + 2, length)
            return name_data.decode('utf-8')
            
        except:
            return ""
            
    def get_game_instance(self) -> int:
        """Get UGameInstance by finding UWorld in GObjects"""
        if not self.base_address:
            return 0
            
        try:
            # Find UWorld instance
            world_ptr = self.get_object_by_name("UWorld")
            if not world_ptr:
                print("[-] Failed to find UWorld instance")
                return 0
                
            # Get GameInstance from UWorld
            game_instance = self.read_long(world_ptr + Engine.UWorld.OwningGameInstance)
            if not game_instance:
                print("[-] Failed to read GameInstance")
                return 0
                
            print(f"[+] Found GameInstance at: 0x{game_instance:X}")
            return game_instance
            
        except Exception as e:
            print(f"[-] Failed to get GameInstance: {e}")
            return 0
            
    def get_local_players(self, game_instance: int) -> List[int]:
        """Get array of local players from GameInstance"""
        if not game_instance:
            return []
            
        try:
            players_array = game_instance + Engine.UGameInstance.LocalPlayers
            array_size = self.read_int(players_array + 0x8)  # TArray size
            array_data = self.read_long(players_array)  # TArray data
            
            if not array_size or not array_data:
                return []
                
            players = []
            for i in range(min(array_size, 10)):  # Limit to 10 players max
                player_ptr = self.read_long(array_data + i * 8)
                if player_ptr:
                    players.append(player_ptr)
                    
            print(f"[+] Found {len(players)} players")
            return players
            
        except Exception as e:
            print(f"[-] Failed to get players: {e}")
            return []
        
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
