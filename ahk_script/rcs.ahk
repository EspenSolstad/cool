#NoEnv
#SingleInstance Force
#Persistent
#InstallKeybdHook
#UseHook
#KeyHistory 0
#HotKeyInterval 1
#MaxHotkeysPerInterval 127
SetWorkingDir %A_ScriptDir%

; Performance settings
SetMouseDelay, -1
SetDefaultMouseSpeed, 0
CoordMode, Mouse, Screen

; Create GUI for debug info
Gui, +AlwaysOnTop
Gui, Add, Text, vDebugText w300 h200
Gui, Show, x0 y0, Debug Info

; Global variables
global EMCol := 0x000000
global ColVn := 64
global ZeroX := A_ScreenWidth // 2
global ZeroY := A_ScreenHeight // 2
global ZoomActive := false
global ZoomSens := 0.5

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
        fov := A_ScreenWidth // 16
    } else {
        fov := A_ScreenWidth // 8
    }
    
    ScanArea.Left := ZeroX - fov
    ScanArea.Top := ZeroY
    ScanArea.Right := ZeroX + fov
    ScanArea.Bottom := ZeroY + (A_ScreenHeight // 64)
    
    NearScan.Left := ZeroX - (fov // 4)
    NearScan.Top := ZeroY - (A_ScreenHeight // 128)
    NearScan.Right := ZeroX + (fov // 4)
    NearScan.Bottom := ZeroY + (A_ScreenHeight // 128)
}

; Initial setup
UpdateScanAreas()

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

; Update debug info with scan areas
UpdateScanInfo() {
    info := "Scan Areas:`n"
    info .= "Near: " NearScan.Left "," NearScan.Top " to " NearScan.Right "," NearScan.Bottom "`n"
    info .= "Wide: " ScanArea.Left "," ScanArea.Top " to " ScanArea.Right "," ScanArea.Bottom "`n"
    info .= "Zoom: " (ZoomActive ? "Active" : "Inactive") "`n"
    info .= "Sens: " ZoomSens
    return info
}

; Enhanced mouse movement
SmoothMove(targetX, targetY) {
    static steps := 10
    
    MouseGetPos, currentX, currentY
    
    moveX := (targetX - currentX) / steps
    moveY := (targetY - currentY) / steps
    
    sensitivity := BaseSens * AimSens
    if (ZoomActive)
        sensitivity := sensitivity * ZoomSens
        
    if (sensitivity > MaxSens)
        sensitivity := MaxSens
    if (sensitivity < MinSens)
        sensitivity := MinSens
    
    moveX := moveX * sensitivity
    moveY := moveY * sensitivity
    
    Loop % steps {
        MouseMove, Round(moveX), Round(moveY), 1, R
        Sleep 1
    }
}

; Target finding
FindTarget() {
    PixelSearch, foundX, foundY, NearScan.Left, NearScan.Top, NearScan.Right, NearScan.Bottom, EMCol, ColVn, Fast RGB
    if (!ErrorLevel)
        return {x: foundX, y: foundY, found: true, area: "near"}
    
    PixelSearch, foundX, foundY, ScanArea.Left, ScanArea.Top, ScanArea.Right, ScanArea.Bottom, EMCol, ColVn, Fast RGB
    if (!ErrorLevel)
        return {x: foundX, y: foundY, found: true, area: "wide"}
    
    return {x: 0, y: 0, found: false, area: "none"}
}

; Recoil compensation
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
    
    deltaY := currentY - lastY
    
    if (ZoomActive)
        deltaY := deltaY / ZoomSens
    
    if (deltaY > 0) {
        recoilY := recoilY + 0.5
        if (recoilY > 5.0)
            recoilY := 5.0
            
        compAmount := recoilY
        if (ZoomActive)
            compAmount := compAmount * ZoomSens
            
        MouseMove, 0, Round(-compAmount), 1, R
    } else {
        recoilY := recoilY * 0.9
    }
    
    lastX := currentX
    lastY := currentY
}

; Main hotkeys and loops
$*~LButton::
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

$*F1::Suspend, Toggle

$*F2::
    static debugVisible := true
    if (debugVisible) {
        Gui, Hide
        debugVisible := false
    } else {
        Gui, Show
        debugVisible := true
    }
return

$*F3::
    static colorIndex := 0
    colors := [0x000000, 0xFF0000, 0x00FF00]
    
    colorIndex := Mod(colorIndex + 1, colors.Length())
    EMCol := colors[colorIndex + 1]
    
    debugInfo := "Color changed to: " . EMCol
    UpdateDebug(debugInfo)
return

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

$*End::
    Gui, Destroy
    ExitApp
return

MsgBox, RCS loaded!`nF1: Toggle`nF2: Debug`nF3: Colors`nNumpad +/-: Base sens`nNumpad */÷: Aim sens`nEnd: Exit
