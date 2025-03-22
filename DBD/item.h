#pragma once
#include <Windows.h>
#include <string>
#include <map>
#include <chrono>
#include <unordered_map>
#include "types.h"
#include "offsets.h"

enum class ItemType {
    NONE = 0,
    MEDKIT = 1,
    TOOLBOX = 2,
    FLASHLIGHT = 3,
    KEY = 4,
    MAP = 5,
    FIRECRACKER = 6
};

enum class ItemRarity {
    COMMON = 0,
    UNCOMMON = 1,
    RARE = 2,
    VERY_RARE = 3,
    ULTRA_RARE = 4
};

struct ItemData {
    ItemType type;
    std::string name;
    float baseCharges;
    float maxCharges;
    float consumptionRate;

    ItemData(ItemType t, const std::string& n, float base, float max, float rate) 
        : type(t), name(n), baseCharges(base), maxCharges(max), consumptionRate(rate) {}
};

static std::map<ItemType, ItemData> ITEM_DATABASE = {
    {ItemType::MEDKIT, ItemData(ItemType::MEDKIT, "Medkit", 24.0f, 32.0f, 1.0f)},
    {ItemType::TOOLBOX, ItemData(ItemType::TOOLBOX, "Toolbox", 16.0f, 32.0f, 1.0f)},
    {ItemType::FLASHLIGHT, ItemData(ItemType::FLASHLIGHT, "Flashlight", 8.0f, 12.0f, 1.0f)},
    {ItemType::KEY, ItemData(ItemType::KEY, "Key", 10.0f, 20.0f, 1.0f)},
    {ItemType::MAP, ItemData(ItemType::MAP, "Map", 20.0f, 30.0f, 1.0f)},
    {ItemType::FIRECRACKER, ItemData(ItemType::FIRECRACKER, "Firecracker", 1.0f, 1.0f, 1.0f)}
};

struct ItemProperties {
    ItemType type;
    float baseCharges;
    float remainingCharges;
    float consumptionRate;
    ItemRarity rarity;
    
    struct {
        int id;
        float modifier;
    } addons[2];
};

class ItemTracker {
public:
    struct ActiveItem {
        ItemProperties properties;
        bool isInUse;
        float lastCharges;
        std::chrono::steady_clock::time_point lastUpdate;
        
        void UpdateCharges(float newCharges) {
            lastCharges = newCharges;
            lastUpdate = std::chrono::steady_clock::now();
        }
    };

    void UpdateItemState(uintptr_t player, const ItemProperties& props) {
        ActiveItem newItem;
        newItem.properties = props;
        newItem.isInUse = false;
        newItem.lastCharges = props.remainingCharges;
        newItem.lastUpdate = std::chrono::steady_clock::now();
        trackedItems[player] = newItem;
    }

    void MonitorCharges(HANDLE hProc, uintptr_t itemAddr) {
        // Monitor item state instead of charges
        uint8_t state;
        if (ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemState), &state, sizeof(uint8_t), nullptr)) {
            for (auto& item : trackedItems) {
                if (item.second.properties.type != ItemType::NONE) {
                    bool isInUse = false;
                    ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::IsInUse), &isInUse, sizeof(bool), nullptr);
                    item.second.isInUse = isInUse;
                }
            }
        }
    }

    std::unordered_map<uintptr_t, ActiveItem> trackedItems;
};

void ProcessAddons(HANDLE hProc, uintptr_t itemAddr, ItemProperties& props) {
    // Read item type and state
    uint8_t type;
    ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemType), &type, sizeof(uint8_t), nullptr);
    props.type = static_cast<ItemType>(type);
    
    uint8_t state;
    ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemState), &state, sizeof(uint8_t), nullptr);
}
