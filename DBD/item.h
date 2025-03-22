#pragma once
#include <Windows.h>
#include <string>
#include <map>
#include <chrono>
#include <unordered_map>

namespace Offsets {
    constexpr auto ItemBase = 0x2A8;
    constexpr auto ItemProperties = 0x40;
    constexpr auto ItemCharges = 0x58;
    constexpr auto ItemAddon1 = 0x88;
    constexpr auto ItemAddon2 = 0x90;
    constexpr auto ItemRarity = 0x64;
    constexpr auto ItemState = 0x70;
}

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
};

const std::map<ItemType, ItemData> ITEM_DATABASE = {
    {ItemType::MEDKIT, {"Medkit", 24.0f, 32.0f, 1.0f}},
    {ItemType::TOOLBOX, {"Toolbox", 16.0f, 32.0f, 1.0f}},
    {ItemType::FLASHLIGHT, {"Flashlight", 8.0f, 12.0f, 1.0f}},
    {ItemType::KEY, {"Key", 10.0f, 20.0f, 1.0f}},
    {ItemType::MAP, {"Map", 20.0f, 30.0f, 1.0f}},
    {ItemType::FIRECRACKER, {"Firecracker", 1.0f, 1.0f, 1.0f}}
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
        trackedItems[player] = {props, false, props.remainingCharges, std::chrono::steady_clock::now()};
    }

    void MonitorCharges(HANDLE hProc, uintptr_t itemAddr) {
        float charges;
        if (ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemCharges), &charges, sizeof(float), nullptr)) {
            for (auto& [player, item] : trackedItems) {
                if (item.lastCharges != charges) {
                    item.UpdateCharges(charges);
                }
            }
        }
    }

    std::unordered_map<uintptr_t, ActiveItem> trackedItems;
};

struct AddonEffect {
    float chargeModifier;
    float speedModifier;
    bool grantsAura;
    std::string description;
};

void ProcessAddons(HANDLE hProc, uintptr_t itemAddr, ItemProperties& props) {
    int addon1ID, addon2ID;
    ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemAddon1), &addon1ID, sizeof(int), nullptr);
    ReadProcessMemory(hProc, (LPCVOID)(itemAddr + Offsets::ItemAddon2), &addon2ID, sizeof(int), nullptr);
    
    props.addons[0].id = addon1ID;
    props.addons[1].id = addon2ID;
    
    // Apply addon modifiers based on IDs
    // This would be expanded with actual addon data
}
