# Game engine offsets and structure layouts
class Engine:
    # Global engine pointers
    GObjects = 0xa80a590
    GNames = 0xa747d40
    GWorld = 0xa8c7160  # Global UWorld pointer
    
    # Core structure offsets
    class UWorld:
        OwningGameInstance = 0x1c8
        PersistentLevel = 0x38
        GameState = 0x168
        
    class UGameInstance:
        LocalPlayers = 0x40
        
    class ACharacter:
        Mesh = 0x328
        RootComponent = 0x1a8
        
    class ADBDPlayer:
        PlayerData = 0xb98
        CharacterInventory = 0xaf8
        
    class ASurvivor:
        BaseOffset = 0x19e0  # Base offset for BP_Camper_Character_C
        
    class AKiller:
        BaseOffset = 0x1ab0  # Base offset for BP_Slasher_Character_C

# UE4 base structure offsets
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
