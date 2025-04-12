#Include %A_ScriptDir%\config.ahk

; Utility Functions for AHK Script

; Initialize the script performance settings
InitializeSettings() {
    #NoEnv
    #SingleInstance Force
    #Persistent
    #InstallKeybdHook
    #UseHook
    #KeyHistory 0
    #HotKeyInterval 1
    #MaxHotkeysPerInterval 127
    
    SetKeyDelay -1, 1
    SetControlDelay -1
    SetMouseDelay -1
    SetWinDelay -1
    SendMode InputThenPlay
    SetBatchLines -1
    ListLines Off
    
    CoordMode Pixel, Screen, RGB
    CoordMode Mouse, Screen
    
    ; Set process priority to high
    PID := DllCall("GetCurrentProcessId")
    Process Priority, %PID%, High
}

; Get the current mouse position
GetMousePos() {
    MouseGetPos, mouseX, mouseY
    return {x: mouseX, y: mouseY}
}

; Calculate distance between two points
CalculateDistance(x1, y1, x2, y2) {
    deltaX := 0.0
    deltaY := 0.0
    deltaX := x2 - x1
    deltaY := y2 - y1
    distance := 0.0
    distance := Sqrt(deltaX * deltaX + deltaY * deltaY)
    return distance
}

; Smooth mouse movement with dynamic compensation
SmoothMove(targetX, targetY, speed := 1.0) {
    static smoothingSteps := 10
    
    mousePos := GetMousePos()
    
    deltaX := 0.0
    deltaY := 0.0
    deltaX := (targetX - mousePos.x) / smoothingSteps
    deltaY := (targetY - mousePos.y) / smoothingSteps
    
    Loop % smoothingSteps {
        moveX := 0
        moveY := 0
        moveX := Round(deltaX * speed)
        moveY := Round(deltaY * speed)
        
        if (Abs(moveX) < 1 && Abs(moveY) < 1)
            break
            
        DllCall("mouse_event", "UInt", 0x01, "Int", moveX, "Int", moveY, "UInt", 0, "Int", 0)
        Sleep 1
    }
}

; Enhanced pixel search with multi-point sampling
EnhancedPixelSearch(x1, y1, x2, y2, color, variation := 0) {
    ; First try exact match
    PixelSearch, foundX, foundY, x1, y1, x2, y2, color, variation, Fast RGB
    if (!ErrorLevel)
        return {x: foundX, y: foundY, found: true}
        
    ; If not found, try with increased variation
    variation += 10
    PixelSearch, foundX, foundY, x1, y1, x2, y2, color, variation, Fast RGB
    if (!ErrorLevel)
        return {x: foundX, y: foundY, found: true}
        
    return {x: 0, y: 0, found: false}
}

; Get screen region for analysis
GetScreenRegion(x, y, width, height) {
    if (width < 1 || height < 1)
        return false
        
    try {
        pBitmap := Gdip_BitmapFromScreen(x "|" y "|" width "|" height)
        return pBitmap
    } catch {
        return false
    }
}

; Calculate movement vector between two points
CalculateMovementVector(x1, y1, x2, y2) {
    deltaX := 0.0
    deltaY := 0.0
    magnitude := 0.0
    
    deltaX := x2 - x1
    deltaY := y2 - y1
    magnitude := Sqrt(deltaX * deltaX + deltaY * deltaY)
    
    return {
        x: deltaX,
        y: deltaY,
        magnitude: magnitude
    }
}

; Apply exponential smoothing to a value
ExponentialSmooth(currentValue, newValue, alpha := 0.5) {
    return (alpha * newValue) + ((1 - alpha) * currentValue)
}
