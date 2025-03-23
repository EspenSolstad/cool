#pragma once
#include <Windows.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include "types.h"

class UI {
public:
    struct Config {
        bool showESP = true;
        bool showHealthBars = true;
        bool showItems = true;
        bool showDistance = false;
        bool showRoles = true;
        float espBoxWidth = 50.0f;
        float espBoxHeight = 100.0f;
    };

    UI() : initialized(false) {}

    bool Init(HWND gameWindow, ID3D11Device* device, ID3D11DeviceContext* context) {
        if (initialized) return true;
        this->device = device;
        this->context = context;
        initialized = true;
        return true;
    }

    void BeginFrame() {
        if (!initialized) return;
    }

    void Render(const std::vector<ESPEntity>& entities) {
        if (!initialized) return;
        // Basic DirectX rendering will be handled by the overlay class
    }

    void EndFrame() {
        if (!initialized) return;
    }

    void Shutdown() {
        if (!initialized) return;
        initialized = false;
    }

    Config& GetConfig() { return config; }

private:
    bool initialized;
    Config config;
    ID3D11Device* device;
    ID3D11DeviceContext* context;
};
