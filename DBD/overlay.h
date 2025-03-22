#pragma once
#include <Windows.h>
#include <d3d11.h>
#include <DirectXMath.h>
#include <vector>
#include "types.h"

#pragma comment(lib, "d3d11.lib")

using namespace DirectX;

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

    void DrawBox(const Vector3& pos, float width, float height, D3DCOLOR color) {
        RECT windowRect;
        GetClientRect(gameWindow, &windowRect);
        
        // World to screen conversion
        float screenX = (pos.x / pos.z) * windowRect.right + windowRect.right/2;
        float screenY = (pos.y / pos.z) * windowRect.bottom + windowRect.bottom/2;
        
        // Draw box corners
        DrawLine(screenX - width/2, screenY - height/2, screenX + width/2, screenY - height/2, color);
        DrawLine(screenX + width/2, screenY - height/2, screenX + width/2, screenY + height/2, color);
        DrawLine(screenX + width/2, screenY + height/2, screenX - width/2, screenY + height/2, color);
        DrawLine(screenX - width/2, screenY + height/2, screenX - width/2, screenY - height/2, color);
    }

    void DrawText(const Vector3& pos, const char* text, D3DCOLOR color) {
        RECT windowRect;
        GetClientRect(gameWindow, &windowRect);
        
        float screenX = (pos.x / pos.z) * windowRect.right + windowRect.right/2;
        float screenY = (pos.y / pos.z) * windowRect.bottom + windowRect.bottom/2;
        
        // Create text layout and draw
        DrawTextA(screenX, screenY, text, color);
    }

private:
    void DrawLine(float x1, float y1, float x2, float y2, D3DCOLOR color) {
        // Create vertex buffer for line
        ID3D11Buffer* vertexBuffer;
        struct Vertex {
            XMFLOAT3 pos;
            D3DCOLOR color;
        } vertices[] = {
            {{x1, y1, 0.0f}, color},
            {{x2, y2, 0.0f}, color}
        };

        D3D11_BUFFER_DESC bd;
        ZeroMemory(&bd, sizeof(bd));
        bd.Usage = D3D11_USAGE_DEFAULT;
        bd.ByteWidth = sizeof(Vertex) * 2;
        bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;

        D3D11_SUBRESOURCE_DATA initData;
        ZeroMemory(&initData, sizeof(initData));
        initData.pSysMem = vertices;

        pDevice->CreateBuffer(&bd, &initData, &vertexBuffer);
        
        // Draw line
        UINT stride = sizeof(Vertex);
        UINT offset = 0;
        pContext->IASetVertexBuffers(0, 1, &vertexBuffer, &stride, &offset);
        pContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_LINELIST);
        pContext->Draw(2, 0);
        
        vertexBuffer->Release();
    }

    void DrawTextA(float x, float y, const char* text, D3DCOLOR color) {
        // Simplified text rendering using GDI for now
        HDC hdc = GetDC(gameWindow);
        SetTextColor(hdc, RGB((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF));
        SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, static_cast<int>(x), static_cast<int>(y), text, static_cast<int>(strlen(text)));
        ReleaseDC(gameWindow, hdc);
    }

    HWND gameWindow;
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    IDXGISwapChain* pSwapChain;
    ID3D11RenderTargetView* renderTarget;
};
