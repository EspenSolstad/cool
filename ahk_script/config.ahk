; Configuration Settings
global EMCol := 0x000000           ; Enemy color to detect
global ColVn := 64                 ; Color variation tolerance
global fovx := 40                  ; Horizontal FOV for targeting
global fovy := 40                  ; Vertical FOV for targeting

; Screen calculations
global A_ScreenCenter := {}
A_ScreenCenter.X := A_ScreenWidth // 2
A_ScreenCenter.Y := A_ScreenHeight // 2

; Anti-shake settings
global AntiShake := {}
AntiShake.X := A_ScreenHeight // 160
AntiShake.Y := A_ScreenHeight // 128

; Scan area calculations
global ScanArea := {}
ScanArea.CFovX := A_ScreenWidth // 8
ScanArea.CFovY := A_ScreenHeight // 64
ScanArea.Left := A_ScreenCenter.X - ScanArea.CFovX
ScanArea.Top := A_ScreenCenter.Y
ScanArea.Right := A_ScreenCenter.X + ScanArea.CFovX
ScanArea.Bottom := A_ScreenCenter.Y + ScanArea.CFovY

; Near aim scan area
global NearAimScan := {}
NearAimScan.Left := A_ScreenCenter.X - AntiShake.X
NearAimScan.Top := A_ScreenCenter.Y - AntiShake.Y
NearAimScan.Right := A_ScreenCenter.X + AntiShake.X
NearAimScan.Bottom := A_ScreenCenter.Y + AntiShake.Y

; Recoil compensation settings
global RecoilConfig := {}
RecoilConfig.SampleRate := 10      ; How often to sample recoil (ms)
RecoilConfig.MaxSamples := 30      ; Maximum samples to store for pattern learning
RecoilConfig.SmoothingFactor := 0.8 ; Smoothing factor for recoil compensation (0-1)
