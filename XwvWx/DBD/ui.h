#pragma once
#include <Windows.h>
#include <d3d11.h>
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include <string>
#include <vector>
#include "types.h"

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

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
        ImVec4 killerColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
        ImVec4 survivorColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
        ImVec4 itemColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
        ImVec4 healthColor = ImVec4(0.0f, 1.0f, 1.0f, 1.0f);
    };

    UI() : initialized(false), showMenu(true) {}

    bool Init(HWND gameWindow, ID3D11Device* device, ID3D11DeviceContext* context) {
        if (initialized) return true;

        // Initialize ImGui
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        
        // Setup style
        ImGui::StyleColorsDark();
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 5.0f;
        style.FrameRounding = 3.0f;
        style.GrabRounding = 3.0f;
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 0.94f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.20f, 0.25f, 0.29f, 0.55f);
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
        
        // Initialize ImGui backends
        if (!ImGui_ImplWin32_Init(gameWindow)) return false;
        if (!ImGui_ImplDX11_Init(device, context)) return false;

        initialized = true;
        return true;
    }

    void BeginFrame() {
        if (!initialized) return;
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
    }

    void Render(const std::vector<ESPEntity>& entities) {
        if (!initialized) return;

        if (showMenu) {
            RenderMainWindow();
            RenderPlayerList(entities);
            RenderStatusPanel();
        }

        // Always show FPS counter
        ImGui::SetNextWindowBgAlpha(0.35f);
        ImGui::Begin("Overlay", nullptr, 
            ImGuiWindowFlags_NoTitleBar | 
            ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_AlwaysAutoResize | 
            ImGuiWindowFlags_NoMove | 
            ImGuiWindowFlags_NoSavedSettings
        );
        ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);
        ImGui::End();
    }

    void EndFrame() {
        if (!initialized) return;
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }

    void Shutdown() {
        if (!initialized) return;
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        initialized = false;
    }

    Config& GetConfig() { return config; }
    void ToggleMenu() { showMenu = !showMenu; }

private:
    void RenderMainWindow() {
        ImGui::SetNextWindowSize(ImVec2(300, 400), ImGuiCond_FirstUseEver);
        ImGui::Begin("DBD Hack", nullptr);

        if (ImGui::CollapsingHeader("ESP Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Checkbox("Enable ESP", &config.showESP);
            ImGui::Checkbox("Show Health Bars", &config.showHealthBars);
            ImGui::Checkbox("Show Items", &config.showItems);
            ImGui::Checkbox("Show Distance", &config.showDistance);
            ImGui::Checkbox("Show Roles", &config.showRoles);
            
            ImGui::SliderFloat("Box Width", &config.espBoxWidth, 20.0f, 100.0f);
            ImGui::SliderFloat("Box Height", &config.espBoxHeight, 50.0f, 200.0f);
        }

        if (ImGui::CollapsingHeader("Colors", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::ColorEdit4("Killer Color", (float*)&config.killerColor);
            ImGui::ColorEdit4("Survivor Color", (float*)&config.survivorColor);
            ImGui::ColorEdit4("Item Color", (float*)&config.itemColor);
            ImGui::ColorEdit4("Health Color", (float*)&config.healthColor);
        }

        ImGui::End();
    }

    void RenderPlayerList(const std::vector<ESPEntity>& entities) {
        ImGui::SetNextWindowSize(ImVec2(250, 400), ImGuiCond_FirstUseEver);
        ImGui::Begin("Players", nullptr);

        int survivors = 0;
        bool killerFound = false;

        for (const auto& entity : entities) {
            if (entity.isKiller) {
                if (!killerFound) {
                    ImGui::TextColored(
                        ImVec4(config.killerColor.x, config.killerColor.y, config.killerColor.z, 1.0f),
                        "Killer"
                    );
                    ImGui::Separator();
                    killerFound = true;
                }
            } else {
                if (survivors == 0) {
                    ImGui::TextColored(
                        ImVec4(config.survivorColor.x, config.survivorColor.y, config.survivorColor.z, 1.0f),
                        "Survivors"
                    );
                    ImGui::Separator();
                }
                survivors++;

                ImGui::Text("%s", entity.name);
                ImGui::ProgressBar(entity.health / 100.0f, ImVec2(-1, 0), "");
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Health: %d%%", entity.health);
                }
            }
        }

        if (!killerFound) ImGui::Text("No killer found");
        if (survivors == 0) ImGui::Text("No survivors found");

        ImGui::End();
    }

    void RenderStatusPanel() {
        ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(200, 70), ImGuiCond_FirstUseEver);
        ImGui::Begin("Status", nullptr, 
            ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_NoMove | 
            ImGuiWindowFlags_NoCollapse
        );

        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Connected");
        ImGui::Text("Players: %d", ImGui::GetIO().MetricsRenderVertices / 100);  // Rough estimate

        ImGui::End();
    }

    bool initialized;
    bool showMenu;
    Config config;
};
