#Include %A_ScriptDir%\utils.ahk
#Include %A_ScriptDir%\recoil.ahk
#Include %A_ScriptDir%\aimbot.ahk

; Initialize script settings
InitializeSettings()

; Hotkeys
$*~LButton::
    AimbotSystem.StartAiming()
    RecoilCompensator.StartCompensation()
    
    Loop {
        if (!GetKeyState("LButton", "P")) {
            AimbotSystem.StopAiming()
            RecoilCompensator.StopCompensation()
            break
        }
        
        ; Update aimbot and recoil compensation
        AimbotSystem.Update()
        RecoilCompensator.CompensateRecoil()
        
        ; Small sleep to prevent excessive CPU usage
        Sleep 1
    }
return

$*~RButton::
    ; Toggle zoom sensitivity handling
    if GetKeyState("RButton", "P") {
        ; Adjust scan areas for zoomed state
        ScanArea.CFovX := A_ScreenWidth // 16  ; Tighter scan area when zoomed
        ScanArea.CFovY := A_ScreenHeight // 128
    } else {
        ; Reset to default scan areas
        ScanArea.CFovX := A_ScreenWidth // 8
        ScanArea.CFovY := A_ScreenHeight // 64
    }
return

; Insert key to toggle the script
$*Insert::
    Suspend, Toggle
    if (A_IsSuspended) {
        AimbotSystem.StopAiming()
        RecoilCompensator.StopCompensation()
    }
return

; Delete key to reload the script
$*Delete::
    Reload
return

; End key to exit the script
$*End::
    ExitApp
return

; Function key toggles
$*F1::
    ; Toggle aimbot
    if (AimbotSystem.isAiming) {
        AimbotSystem.StopAiming()
    } else {
        AimbotSystem.StartAiming()
    }
return

$*F2::
    ; Toggle recoil control
    if (RecoilCompensator.isCompensating) {
        RecoilCompensator.StopCompensation()
    } else {
        RecoilCompensator.StartCompensation()
    }
return

$*F3::
    ; Cycle through different enemy colors
    static colorIndex := 0
    colors := [0x000000, 0xFF0000, 0x00FF00]  ; Add more colors as needed
    
    colorIndex := Mod(colorIndex + 1, colors.Length())
    EMCol := colors[colorIndex + 1]
return

$*F4::
    ; Toggle debug visualization (could add later)
return

; Initialize message
MsgBox, Script loaded! Use Insert to toggle, Delete to reload, End to exit.`nF1-F4 for additional controls.
