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
        
        # Get GameInstance from UWorld
        game_instance = self.memory.get_game_instance()
        if not game_instance:
            return
            
        # Get local players array
        players = self.memory.get_local_players(game_instance)
        if not players:
            return
            
        # Process each player
        for player_ptr in players:
            if player_ptr:
                self._process_player(player_ptr)
    
    def _process_player(self, address: int) -> None:
        """Process a single player entity"""
        if not address:
            return
            
        try:
            # Get mesh component for position
            mesh = self.memory.read_long(address + Engine.ACharacter.Mesh)
            if not mesh:
                return
                
            # Get root component for position
            root = self.memory.read_long(address + Engine.ACharacter.RootComponent)
            if not root:
                return
                
            # Get position from root component
            pos_raw = self.memory.read_vec3(root + 0x128)  # Component relative location
            position = Vector3(*pos_raw)
            
            # Check if killer or survivor based on vtable/class name
            player_data = self.memory.read_long(address + Engine.ADBDPlayer.PlayerData)
            if not player_data:
                return
                
            # Get role from player data
            role = self.memory.read_bytes(player_data + Offsets.GameRole, 1)[0]
            is_killer = (role == 1)
            
            # Handle survivor-specific data
            health = 100
            item_name = "None"
            being_carried = False
            
            if not is_killer:
                # Get survivor state
                state_offset = Engine.ASurvivor.BaseOffset + Offsets.CamperState
                camper_state = self.memory.read_bytes(address + state_offset, 1)[0]
                health = 100 if camper_state == 0 else 50 if camper_state == 1 else 0
                
                # Check if being carried
                carry_offset = Engine.ASurvivor.BaseOffset + Offsets.CarryingPlayer
                carrying_player = self.memory.read_long(address + carry_offset)
                being_carried = carrying_player != 0
                
                # Get inventory items
                inventory = self.memory.read_long(address + Engine.ADBDPlayer.CharacterInventory)
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
            
        except Exception as e:
            print(f"[-] Failed to process player at {hex(address)}: {e}")
