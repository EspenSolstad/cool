from dataclasses import dataclass
from typing import List, Tuple, Optional
from .memory import MemoryReader
from .offsets import Offsets, UE4, Engine

@dataclass
class Vector3:
    x: float
    y: float
    z: float

@dataclass
class Entity:
    position: Vector3
    is_killer: bool
    health: int
    name: str
    item_name: str = "None"
    being_carried: bool = False
    
    @property
    def color(self) -> Tuple[int, int, int]:
        """Get entity color based on role and state"""
        if self.is_killer:
            return (255, 0, 0)  # Red for killer
        if self.being_carried:
            return (255, 165, 0)  # Orange for carried survivors
        if self.health <= 0:
            return (128, 128, 128)  # Gray for dying state
        if self.health <= 50:
            return (255, 255, 0)  # Yellow for injured state
        return (0, 255, 0)  # Green for healthy survivors

class EntityManager:
    def __init__(self, memory: MemoryReader):
        self.memory = memory
        self.entities: List[Entity] = []
        self.last_update = 0
        
    def update(self) -> None:
        """Update all entity information"""
        self.entities.clear()
        
        # Get UWorld
        uworld_ptr = self.memory.base_address + Engine.GWorld
        uworld = self.memory.read_long(uworld_ptr)
        if not uworld:
            return
            
        # Get GameState
        game_state = self.memory.read_long(uworld)
        if not game_state:
            return
            
        # Get player array using pattern or direct offset
        player_array = self.memory.get_pointer_chain(game_state, [Offsets.PlayerData])
        if not player_array:
            return
            
        # Read array size
        count = self.memory.read_int(player_array + 0x8)
        if count <= 0 or count > 8:  # Max 8 players in DBD
            return
            
        # Get data pointer
        data_ptr = self.memory.read_long(player_array)
        if not data_ptr:
            return
            
        # Process each player
        for i in range(count):
            player_ptr = self.memory.read_long(data_ptr + (i * 8))
            if not player_ptr:
                continue
                
            self._process_player(player_ptr)
    
    def _process_player(self, address: int) -> None:
        """Process a single player entity"""
        if not address:
            return
            
        # Get player state
        player_state = self.memory.read_long(address + Offsets.PlayerData)
        if not player_state:
            return
            
        # Get role (killer vs survivor)
        role = self.memory.read_bytes(player_state + Offsets.GameRole, 1)[0]
        is_killer = (role == 1)
        
        # Get root component for position
        root_comp = self.memory.read_long(address + UE4.Children)
        if not root_comp:
            return
            
        # Get position
        pos_raw = self.memory.read_vec3(root_comp + UE4.FieldNext)
        position = Vector3(*pos_raw)
        
        # Get survivor state if not killer
        health = 100
        if not is_killer:
            camper_state = self.memory.read_bytes(address + Offsets.CamperState, 1)[0]
            health = 100 if camper_state == 0 else 50 if camper_state == 1 else 0
        
        # Check if being carried
        carrying_player = self.memory.read_long(address + Offsets.CarryingPlayer)
        being_carried = carrying_player != 0
        
        # Get item info for survivors
        item_name = "None"
        if not is_killer:
            inventory = self.memory.read_long(address + Offsets.CharacterInventory)
            if inventory:
                item_count = self.memory.read_int(inventory + Offsets.ItemCount)
                if item_count > 0:
                    item_type = self.memory.read_bytes(inventory + Offsets.ItemType, 1)[0]
                    is_in_use = bool(self.memory.read_bytes(inventory + Offsets.IsInUse, 1)[0])
                    
                    if is_in_use:
                        item_names = {
                            0: "Medkit",
                            1: "Flashlight",
                            2: "Toolbox",
                            3: "Map",
                            4: "Key"
                        }
                        item_name = item_names.get(item_type, "Unknown")
        
        # Create entity
        entity = Entity(
            position=position,
            is_killer=is_killer,
            health=health,
            name="KILLER" if is_killer else f"Survivor - {item_name}",
            item_name=item_name,
            being_carried=being_carried
        )
        
        self.entities.append(entity)
