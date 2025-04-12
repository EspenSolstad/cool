import time
import random
from typing import Optional, Tuple, List
import psutil
from pymem import Pymem
from pymem.process import module_from_name
import numpy as np

class MemoryReader:
    def __init__(self):
        self.pm: Optional[Pymem] = None
        self.base_address: int = 0
        self.process_name = "DeadByDaylight-Win64-Shipping.exe"
        
    def attach(self) -> bool:
        """Attach to the DBD process"""
        try:
            # Add random delay to avoid detection patterns
            time.sleep(random.uniform(0.1, 0.3))
            
            # Find process
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == self.process_name:
                    self.pm = Pymem(self.process_name)
                    module = module_from_name(self.pm.process_handle, self.process_name)
                    if module:
                        self.base_address = module.lpBaseOfDll
                        return True
            return False
        except Exception as e:
            print(f"Failed to attach: {e}")
            return False

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from memory with random delays"""
        if not self.pm:
            return b''
        
        # Random small delay
        time.sleep(random.uniform(0.001, 0.005))
        
        try:
            return self.pm.read_bytes(address, size)
        except:
            return b''

    def read_int(self, address: int) -> int:
        """Read 32-bit integer"""
        if not self.pm:
            return 0
        try:
            return int.from_bytes(self.read_bytes(address, 4), byteorder='little')
        except:
            return 0

    def read_long(self, address: int) -> int:
        """Read 64-bit integer"""
        if not self.pm:
            return 0
        try:
            return int.from_bytes(self.read_bytes(address, 8), byteorder='little')
        except:
            return 0

    def read_float(self, address: int) -> float:
        """Read 32-bit float"""
        if not self.pm:
            return 0.0
        try:
            return np.frombuffer(self.read_bytes(address, 4), dtype=np.float32)[0]
        except:
            return 0.0

    def read_vec3(self, address: int) -> Tuple[float, float, float]:
        """Read Vector3 (3 floats)"""
        if not self.pm:
            return (0.0, 0.0, 0.0)
        try:
            data = np.frombuffer(self.read_bytes(address, 12), dtype=np.float32)
            return (data[0], data[1], data[2])
        except:
            return (0.0, 0.0, 0.0)

    def read_string(self, address: int, size: int = 32) -> str:
        """Read string with maximum size"""
        if not self.pm:
            return ""
        try:
            data = self.read_bytes(address, size)
            string = data.split(b'\x00')[0]
            return string.decode('utf-8')
        except:
            return ""

    def find_pattern(self, pattern: bytes, mask: str) -> int:
        """Find pattern in process memory"""
        if not self.pm or not self.base_address:
            return 0

        try:
            # Read larger chunks to reduce API calls
            chunk_size = 0x1000
            current_addr = self.base_address
            
            while current_addr < self.base_address + 0x10000000:  # Search first 256MB
                # Random delay between chunks
                time.sleep(random.uniform(0.001, 0.003))
                
                chunk = self.read_bytes(current_addr, chunk_size)
                if not chunk:
                    break

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

        except Exception as e:
            print(f"Pattern scan failed: {e}")
            
        return 0

    def get_pointer_chain(self, base: int, offsets: List[int]) -> int:
        """Follow pointer chain starting at base address"""
        if not self.pm:
            return 0
            
        addr = base
        try:
            for offset in offsets:
                if addr == 0:
                    return 0
                addr = self.read_long(addr)
                if addr == 0:
                    return 0
                addr += offset
            return addr
        except:
            return 0
