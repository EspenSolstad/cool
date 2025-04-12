#NoEnv
#SingleInstance Force
#Persistent
#InstallKeybdHook
#UseHook
SetWorkingDir %A_ScriptDir%

; Create GUI for debug info
Gui, +AlwaysOnTop
Gui, Add, Text, vDebugText w300 h150
Gui, Show, x0 y0, Debug Info

; Function to update debug display
UpdateDebug(info) {
    static startTime := A_TickCount
    timeRunning := (A_TickCount - startTime) // 1000
    
    info .= "`n=================`n"
    info .= "Running: " timeRunning "s`n"
    info .= "Status: " (A_IsSuspended ? "PAUSED" : "ACTIVE") "`n"
    info .= "Color: " EMCol "`n"
    info .= "Base Sens: " BaseSens "`n"
    info .= "Aim Sens: " AimSens "`n"
    info .= "Effective: " Round(BaseSens * AimSens * (ZoomActive ? ZoomSens : 1.0), 2)
    
    GuiControl,, DebugText, %info%
}

; Global variables with proper initialization
global EMCol := 0x000000
global ColVn := 64
global ZeroX := A_ScreenWidth // 2
global ZeroY := A_ScreenHeight // 2
global ZoomActive := false
global ZoomSens := 0.5  ; Adjust this to match your in-game zoom sensitivity

; Sensitivity settings
global BaseSens := 1.0
global AimSens := 0.8
global MinSens := 0.1
global MaxSens := 2.0

; Scan areas
global ScanArea := {}
global NearScan := {}

; Initialize scan areas
UpdateScanAreas() {
    if (ZoomActive) {
        fov := A_ScreenWidth // 16  ; Smaller FOV when zoomed
    } else {
        fov := A_ScreenWidth // 8   ; Normal FOV
    }
    
    ScanArea.Left := ZeroX - fov
    ScanArea.Top := ZeroY
    ScanArea.Right := ZeroX + fov
    ScanArea.Bottom := ZeroY + (A_ScreenHeight // 64)
    
    ; Near scan area (1/4 of main scan area)
    NearScan.Left := ZeroX - (fov // 4)
    NearScan.Top := ZeroY - (A_ScreenHeight // 128)
    NearScan.Right := ZeroX + (fov // 4)
    NearScan.Bottom := ZeroY + (A_ScreenHeight // 128)
}

; Initial scan area setup
UpdateScanAreas()

; Enhanced mouse movement function with sensitivity handling
SmoothMove(targetX, targetY) {
    static steps := 10
    
    MouseGetPos, currentX, currentY
    
    ; Calculate base movement
    moveX := (targetX - currentX) / steps
    moveY := (targetY - currentY) / steps
    
    ; Apply sensitivity adjustments
    sensitivity := BaseSens * AimSens
    if (ZoomActive)
        sensitivity := sensitivity * ZoomSens
        
    ; Clamp sensitivity
    if (sensitivity > MaxSens)
        sensitivity := MaxSens
    if (sensitivity < MinSens)
        sensitivity := MinSens
    
    ; Apply sensitivity
    moveX := moveX * sensitivity
    moveY := moveY * sensitivity
    
    Loop % steps {
        DllCall("mouse_event", "UInt", 0x01, 
                "Int", Round(moveX), 
                "Int", Round(moveY), 
                "UInt", 0, "Int", 0)
        Sleep 1
    }
}

; Basic pixel search
FindTarget() {
    ; First check near scan area
    PixelSearch, foundX, foundY, NearScan.Left, NearScan.Top, NearScan.Right, NearScan.Bottom, EMCol, ColVn, Fast RGB
    if (!ErrorLevel) {
        return {x: foundX, y: foundY, found: true, area: "near"}
    }
    
    ; If not found, check wider area
    PixelSearch, foundX, foundY, ScanArea.Left, ScanArea.Top, ScanArea.Right, ScanArea.Bottom, EMCol, ColVn, Fast RGB
    if (!ErrorLevel) {
        return {x: foundX, y: foundY, found: true, area: "wide"}
    }
    
    return {x: 0, y: 0, found: false, area: "none"}
}

; Update debug info with scan areas
UpdateScanInfo() {
    info := "Scan Areas:`n"
    info .= "Near: " NearScan.Left "," NearScan.Top " to " NearScan.Right "," NearScan.Bottom "`n"
    info .= "Wide: " ScanArea.Left "," ScanArea.Top " to " ScanArea.Right "," ScanArea.Bottom "`n"
    info .= "Zoom: " (ZoomActive ? "Active" : "Inactive") "`n"
    info .= "Sens: " ZoomSens
    return info
}

; Basic recoil compensation
CompensateRecoil() {
    static lastX := 0
    static lastY := 0
    static recoilY := 0.0
    
    MouseGetPos, currentX, currentY
    
    if (lastX = 0) {
        lastX := currentX
        lastY := currentY
        return
    }
    
    ; Calculate movement since last check
    deltaY := currentY - lastY
    
    ; Apply zoom sensitivity if active
    if (ZoomActive)
        deltaY := deltaY / ZoomSens
    
    ; If we detect upward recoil (positive Y movement)
    if (deltaY > 0) {
        ; Gradually increase compensation
        recoilY := recoilY + 0.5
        if (recoilY > 5.0)
            recoilY := 5.0
            
        ; Calculate compensation amount
        compAmount := recoilY
        if (ZoomActive)
            compAmount := compAmount * ZoomSens
            
        ; Apply downward compensation
        DllCall("mouse_event", "UInt", 0x01, 
                "Int", 0, 
                "Int", Round(-compAmount), 
                "UInt", 0, "Int", 0)
    } else {
        ; Gradually decrease compensation
        recoilY := recoilY * 0.9
    }
    
    lastX := currentX
    lastY := currentY
}

; Handle zoom state
$*~RButton::
    ZoomActive := true
    UpdateScanAreas()
    debugInfo := "Zoom: Active`nSens: " ZoomSens
    UpdateDebug(debugInfo)
return

$*~RButton Up::
    ZoomActive := false
    UpdateScanAreas()
    debugInfo := "Zoom: Inactive"
    UpdateDebug(debugInfo)
return

; Main loop
$*~LButton::
    ; Reset recoil tracking
    lastX := 0
    lastY := 0
    recoilY := 0.0
    
    Loop {
        if (!GetKeyState("LButton", "P"))
            break
            
        target := FindTarget()
        if (target.found) {
            SmoothMove(target.x, target.y)
            debugInfo := "Target Found (" target.area ")`nX: " target.x "`nY: " target.y
        } else {
            debugInfo := "No Target Found"
        }
        
        MouseGetPos, currentX, currentY
        debugInfo .= "`nMouse: " currentX "," currentY
        debugInfo .= "`nRecoil: " recoilY
        debugInfo .= "`n`n" UpdateScanInfo()
        
        UpdateDebug(debugInfo)
        CompensateRecoil()
        Sleep 1
    }
return

; Hotkeys
$*F1::Suspend, Toggle

$*F2::  ; Toggle debug window
    static debugVisible := true
    if (debugVisible) {
        Gui, Hide
        debugVisible := false
    } else {
        Gui, Show
        debugVisible := true
    }
return

$*F3::  ; Cycle target colors
    static colorIndex := 0
    colors := [0x000000, 0xFF0000, 0x00FF00]  ; Black, Red, Green
    
    colorIndex := Mod(colorIndex + 1, colors.Length())
    EMCol := colors[colorIndex + 1]
    
    debugInfo := "Color changed to: " . EMCol
    UpdateDebug(debugInfo)
return

; Sensitivity adjustment hotkeys
$*NumpadAdd::
    BaseSens := Min(BaseSens + 0.1, MaxSens)
    debugInfo := "Base Sensitivity: " BaseSens
    UpdateDebug(debugInfo)
return

$*NumpadSub::
    BaseSens := Max(BaseSens - 0.1, MinSens)
    debugInfo := "Base Sensitivity: " BaseSens
    UpdateDebug(debugInfo)
return

$*NumpadMult::
    AimSens := Min(AimSens + 0.1, MaxSens)
    debugInfo := "Aim Sensitivity: " AimSens
    UpdateDebug(debugInfo)
return

$*NumpadDiv::
    AimSens := Max(AimSens - 0.1, MinSens)
    debugInfo := "Aim Sensitivity: " AimSens
    UpdateDebug(debugInfo)
return

$*End::  ; Clean exit
    Gui, Destroy
    ExitApp
return

MsgBox, Simple script loaded!`nF1 to toggle`nF2 to toggle debug`nF3 to cycle colors`nNumpad +/- Base sens`nNumpad */÷ Aim sens`nEnd to exit`nHold left mouse to activate
