#Include %A_ScriptDir%\utils.ahk

; Aimbot system for target detection and tracking
class Aimbot {
    __New() {
        this.isAiming := false
        this.currentTarget := {x: 0, y: 0, found: false}
        this.lastTargetPos := {x: 0, y: 0}
        this.lastScanTime := 0
        this.consecutiveHits := 0
        
        ; Target prediction
        this.targetVelocity := {x: 0, y: 0}
        this.lastUpdateTime := 0
    }
    
    ; Start the aimbot
    StartAiming() {
        this.isAiming := true
        this.lastScanTime := A_TickCount
        this.currentTarget := {x: 0, y: 0, found: false}
    }
    
    ; Stop the aimbot
    StopAiming() {
        this.isAiming := false
        this.consecutiveHits := 0
    }
    
    ; Scan for targets using enhanced pixel search
    ScanForTarget() {
        if (!this.isAiming)
            return {found: false}
            
        ; First check near aim area for faster response
        result := EnhancedPixelSearch(
            NearAimScan.Left, NearAimScan.Top,
            NearAimScan.Right, NearAimScan.Bottom,
            EMCol, ColVn
        )
        
        ; If target not found in near area, scan wider area
        if (!result.found) {
            result := EnhancedPixelSearch(
                ScanArea.Left, ScanArea.Top,
                ScanArea.Right, ScanArea.Bottom,
                EMCol, ColVn
            )
        }
        
        ; Update target information if found
        if (result.found) {
            currentTime := A_TickCount
            timeDelta := (currentTime - this.lastUpdateTime) / 1000.0  ; Convert to seconds
            
            ; Calculate target velocity if we have previous position
            if (this.currentTarget.found) {
                this.targetVelocity.x := (result.x - this.lastTargetPos.x) / timeDelta
                this.targetVelocity.y := (result.y - this.lastTargetPos.y) / timeDelta
            }
            
            ; Update positions and time
            this.lastTargetPos.x := result.x
            this.lastTargetPos.y := result.y
            this.lastUpdateTime := currentTime
            
            ; Predict target position based on velocity
            predictedX := result.x + (this.targetVelocity.x * 0.05)  ; 50ms prediction
            predictedY := result.y + (this.targetVelocity.y * 0.05)
            
            this.currentTarget := {
                x: predictedX,
                y: predictedY,
                found: true
            }
            
            this.consecutiveHits++
        } else {
            this.consecutiveHits := 0
            this.currentTarget.found := false
        }
        
        return this.currentTarget
    }
    
    ; Calculate aim angle and move mouse
    AimAtTarget() {
        if (!this.isAiming || !this.currentTarget.found)
            return false
            
        ; Get current mouse position
        currentPos := GetMousePos()
        
        ; Calculate distance to target
        distance := CalculateDistance(
            currentPos.x, currentPos.y,
            this.currentTarget.x, this.currentTarget.y
        )
        
        ; Adjust aim speed based on distance and consecutive hits
        aimSpeed := this.CalculateAimSpeed(distance)
        
        ; Move mouse smoothly to target
        SmoothMove(
            this.currentTarget.x,
            this.currentTarget.y,
            aimSpeed
        )
        
        return true
    }
    
    ; Calculate dynamic aim speed based on various factors
    CalculateAimSpeed(distance) {
        ; Base speed starts at 1.0
        baseSpeed := 1.0
        
        ; Adjust speed based on distance
        if (distance > 400)
            baseSpeed *= 0.7
        else if (distance > 200)
            baseSpeed *= 0.85
        
        ; Adjust speed based on consecutive hits
        if (this.consecutiveHits > 5)
            baseSpeed *= 1.2
        else if (this.consecutiveHits > 2)
            baseSpeed *= 1.1
            
        ; Ensure speed stays within reasonable bounds
        return Min(Max(baseSpeed, 0.5), 1.5)
    }
    
    ; Main update function to be called in the aim loop
    Update() {
        if (!this.isAiming)
            return
            
        target := this.ScanForTarget()
        if (target.found)
            this.AimAtTarget()
    }
}

; Create global aimbot instance
global AimbotSystem := new Aimbot()
