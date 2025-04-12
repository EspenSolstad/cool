# Game engine offsets ported from C++ version
class Engine:
    GObjects = 0xa731510
    GNames = 0xA66ECC0
    GWorld = 0xA8C7160
    PEOffset = 0x3B56050

# UE4 structure offsets
class UE4:
    # UStruct
    Children = 0x50
    SuperStruct = 0x48
    StructSize = 0x60
    MinAlignment = 0x64
    
    # UClass
    CastFlags = 0xE0
    ClassDefaultObject = 0x120
    
    # UFunction
    FunctionFlags = 0xB8
    ExecFunction = 0xE0
    
    # Property System
    ChildProperties = 0x58
    FieldNext = 0x20
    FieldName = 0x28
    FieldFlags = 0x34
    PropertySize = 0x80
    
    # Property specifics
    ElementSize = 0x3C
    ArrayDim = 0x38
    Offset_Internal = 0x4C
    PropertyFlags = 0x40
    
    # Container properties
    ArrayInner = 0x80
    SetElement = 0x80
    MapBase = 0x80
    
    # Text handling
    TextSize = 0x18
    TextDataOffset = 0x0
    InTextDataStringOffset = 0x30

# Game-specific offsets
class Offsets:
    # From ADBDPlayer
    CharacterInventory = 0xaf8  # _characterInventoryComponent
    PlayerData = 0xb98         # _playerData
    CarryingPlayer = 0xbf8     # _carryingPlayer
    InteractingPlayer = 0xc08  # _interactingPlayer
    CamperState = 0xb70        # CurrentCamperState
    
    # From ACollectable
    ItemCount = 0x520          # _itemCount
    ItemType = 0x548           # _itemType
    ItemAddons = 0x500         # _itemAddons array
    ItemState = 0x4f8          # _state
    IsInUse = 0x54e            # _isInUse
    
    # From ADBDPlayerState
    GameRole = 0x3fa           # GameRole
    PlayerGameState = 0x4d0    # OnPlayerGameStateChanged
    PlayerCustomization = 0x600 # _playerCustomization

# Memory scanning patterns
class Patterns:
    # Core engine patterns
    UWORLD = (
        b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x85\xC9\x74\x06\x48\x8B\x49\x70",
        "xxx????xxx????xxxxxxxxxx"
    )
    
    # Game state patterns
    GAMESTATE = (
        b"\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x20\x48\x8B\xD9\x41\x8B\xF0",
        "xxxx?xxxx?xxxxxxxxxxx"
    )
    
    # Player patterns
    PLAYER_ARRAY = (
        b"\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x01\x48\x8B\x40\x58",
        "xxx????xxxxxxx"
    )
    
    # Level actors pattern
    LEVEL_ACTORS = (
        b"\x48\x8B\x89\x00\x00\x00\x00\x48\x85\xC9\x74\x06\x48\x8B\x01",
        "xxx????xxxxxxxx"
    )
