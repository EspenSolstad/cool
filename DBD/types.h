#pragma once
#include <Windows.h>

struct Vector3 {
    float x, y, z;
};

// Define D3DCOLOR since we're not including d3d9.h
typedef DWORD D3DCOLOR;
#define D3DCOLOR_ARGB(a,r,g,b) \
    ((D3DCOLOR)((((a)&0xff)<<24)|(((r)&0xff)<<16)|(((g)&0xff)<<8)|((b)&0xff)))

struct ESPEntity {
    Vector3 position;
    bool isKiller;
    int health;
    const char* name;
    D3DCOLOR color;
};

namespace Colors {
    const D3DCOLOR Survivor = D3DCOLOR_ARGB(255, 0, 255, 0);    // Green
    const D3DCOLOR Killer = D3DCOLOR_ARGB(255, 255, 0, 0);      // Red
    const D3DCOLOR Item = D3DCOLOR_ARGB(255, 255, 255, 0);      // Yellow
    const D3DCOLOR Health = D3DCOLOR_ARGB(255, 0, 255, 255);    // Cyan
}
