#pragma once
#include <Windows.h>
#include <d3d11.h>
#include <DirectXMath.h>
#include <vector>
#include "offsets.h"

#pragma comment(lib, "d3d11.lib")

using namespace DirectX;

struct ESPEntity {
    Vector3 position;
    bool isKiller;
    int health;
    const char* name;
    D3DCOLOR color;
};

class Overlay {
public:
    Overlay() : gameWindow(nullptr), pDevice(nullptr), pContext(nullptr), 
                pSwapChain(nullptr), renderTarget(nullptr) {}
    
    bool Init() {
        gameWindow = FindWindowA("DeadByDaylight", nullptr);
        if (!gameWindow) return false;

        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = gameWindow;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = { 
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_0,
        };

        if (FAILED(D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION, &sd,
            &pSwapChain, &pDevice, &featureLevel, &pContext))) {
            return false;
        }

        ID3D11Texture2D* pBackBuffer;
        pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
        pDevice->CreateRenderTargetView(pBackBuffer, nullptr, &renderTarget);
        pBackBuffer->Release();

        return true;
    }

    void BeginScene() {
        pContext->OMSetRenderTargets(1, &renderTarget, nullptr);
    }

    void EndScene() {
        pSwapChain->Present(1, 0);
    }

    void DrawBox(Vector3 pos, float width, float height, D3DCOLOR color) {
        // Convert world position to screen position
        XMVECTOR worldPos = XMVectorSet(pos.x, pos.y, pos.z, 1.0f);
        RECT windowRect;
        GetClientRect(gameWindow, &windowRect);
        
        // Simple perspective projection (you'd need to get actual game view matrix)
        float screenX = (pos.x / pos.z) * windowRect.right + windowRect.right/2;
        float screenY = (pos.y / pos.z) * windowRect.bottom + windowRect.bottom/2;
        
        // Draw box corners
        DrawLine(screenX - width/2, screenY - height/2, screenX + width/2, screenY - height/2, color);
        DrawLine(screenX + width/2, screenY - height/2, screenX + width/2, screenY + height/2, color);
        DrawLine(screenX + width/2, screenY + height/2, screenX - width/2, screenY + height/2, color);
        DrawLine(screenX - width/2, screenY + height/2, screenX - width/2, screenY - height/2, color);
    }

    void DrawText(Vector3 pos, const char* text, D3DCOLOR color) {
        // Convert world position to screen position (similar to DrawBox)
        RECT windowRect;
        GetClientRect(gameWindow, &windowRect);
        
        float screenX = (pos.x / pos.z) * windowRect.right + windowRect.right/2;
        float screenY = (pos.y / pos.z) * windowRect.bottom + windowRect.bottom/2;
        
        // Draw text at screen position
        // You'd implement actual text rendering here
    }

private:
    void DrawLine(float x1, float y1, float x2, float y2, D3DCOLOR color) {
        // Implement line drawing using ID3D11DeviceContext
    }

    HWND gameWindow;
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    IDXGISwapChain* pSwapChain;
    ID3D11RenderTargetView* renderTarget;
};
