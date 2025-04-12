# Game engine offsets and structure layouts
class Engine:
    # Global engine pointers
    GObjects = 0xa814790  # FChunkedFixedUObjectArray
    GNames = 0xA751F40   # FNamePool
    PEOffset = 0x3BCE2A0
    
    # Name pool configuration
    NameBlockOffsetBits = 0x10
    
    # Field system configuration
    FNameIndex = 0x18  # FName.Index offset in UObject
    
    # Core structure offsets
    class FChunkedFixedUObjectArray:
        NumElements = 0x10
        MaxElements = 0x14
        Chunks = 0x18
        ChunkSize = 0x4000
        
    class FNamePool:
        Blocks = 0x0
        CurrentBlock = 0x8
        CurrentByteCursor = 0xC
    class ULevel:
        Actors = 0xA0  # TArray<AActor*>
        
    class UWorld:
        PersistentLevel = 0x38
        GameState = 0x168
        OwningGameInstance = 0x1c8
        
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
    # Core structure offsets from dump
    class UStruct:
        Children = 0x50          # Off::UStruct::Children
        SuperStruct = 0x48       # Off::UStruct::SuperStruct
        Size = 0x60              # Off::UStruct::Size
        MinAlignment = 0x64      # Off::UStruct::MinAlignemnts
        ChildProperties = 0x58   # Off::UStruct::ChildProperties
        
    class UClass:
        CastFlags = 0xE0        # Off::UClass::CastFlags
        ClassDefaultObject = 0x120  # Off::UClass::ClassDefaultObject
        
    class UFunction:
        FunctionFlags = 0xB8    # Off::UFunction::FunctionFlags
        ExecFunction = 0xE0     # Off::UFunction::ExecFunction
    
    # FField system from dump
    class FField:
        Next = 0x20            # Off::FField::Next
        Name = 0x28            # Off::FField::Name
        Flags = 0x34           # Off::FField::Flags
        
    class FProperty:
        ElementSize = 0x3C     # Off::Property::ElementSize
        ArrayDim = 0x38        # Off::Property::ArrayDim
        Offset_Internal = 0x4C # Off::Property::Offset_Internal
        PropertyFlags = 0x40   # Off::Property::PropertyFlags
        Size = 0x80           # UPropertySize
    
    # Property specifics
    ElementSize = 0x3C
    ArrayDim = 0x38
    Offset_Internal = 0x4C
    PropertyFlags = 0x40
    
    # Container properties from dump
    class Container:
        ArrayInner = 0x80     # Off::ArrayProperty::Inner
        SetElement = 0x80     # Off::SetProperty::ElementProp
        MapBase = 0x80        # Off::MapProperty::Base
    
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
