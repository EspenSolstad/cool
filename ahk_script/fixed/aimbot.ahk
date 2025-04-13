#Include utils.ahk

; Aimbot system for target detection and tracking
class Aimbot {
    __New() {
        ; Initialize control flags
        this.isAiming := false
        
        ; Initialize target tracking
        this.currentTarget := {x: 0.0, y: 0.0, found: false}
        this.lastTargetPos := {x: 0.0, y: 0.0}
        
        ; Initialize timing variables
        this.lastScanTime := 0
        this.lastUpdateTime := 0
        
        ; Initialize hit tracking
        this.consecutiveHits := 0
        
        ; Initialize prediction system
        this.targetVelocity := {x: 0.0, y: 0.0}
        
        ; Initialize temporary calculation storage
        this.tempCalc := {
            deltaX: 0.0,
            deltaY: 0.0,
            distance: 0.0,
            speed: 0.0
        }
    }
    
    ; Start the aimbot
    StartAiming() {
        ; Reset control flags
        this.isAiming := true
        
        ; Reset timing
        this.lastScanTime := A_TickCount
        this.lastUpdateTime := A_TickCount
        
        ; Reset target tracking
        this.currentTarget := {x: 0.0, y: 0.0, found: false}
        this.lastTargetPos := {x: 0.0, y: 0.0}
        
        ; Reset velocity
        this.targetVelocity.x := 0.0
        this.targetVelocity.y := 0.0
        
        ; Reset hit tracking
        this.consecutiveHits := 0
        
        ; Reset temporary calculations
        this.tempCalc.deltaX := 0.0
        this.tempCalc.deltaY := 0.0
        this.tempCalc.distance := 0.0
        this.tempCalc.speed := 0.0
    }
    
    ; Stop the aimbot
    StopAiming() {
        ; Reset control flags
        this.isAiming := false
        
        ; Reset hit tracking
        this.consecutiveHits := 0
        
        ; Reset target tracking
        this.currentTarget.found := false
        this.currentTarget.x := 0.0
        this.currentTarget.y := 0.0
        
        ; Reset velocity
        this.targetVelocity.x := 0.0
        this.targetVelocity.y := 0.0
        
        ; Reset temporary calculations
        this.tempCalc.deltaX := 0.0
        this.tempCalc.deltaY := 0.0
        this.tempCalc.distance := 0.0
        this.tempCalc.speed := 0.0
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
            timeDelta := 0.0
            timeDelta := (currentTime - this.lastUpdateTime) / 1000.0  ; Convert to seconds
            
            ; Calculate target velocity if we have previous position
            if (this.currentTarget.found) {
                deltaX := 0.0
                deltaY := 0.0
                deltaX := (result.x - this.lastTargetPos.x)
                deltaY := (result.y - this.lastTargetPos.y)
                this.targetVelocity.x := deltaX / timeDelta
                this.targetVelocity.y := deltaY / timeDelta
            }
            
            ; Update positions and time
            this.lastTargetPos.x := result.x
            this.lastTargetPos.y := result.y
            this.lastUpdateTime := currentTime
            
            ; Predict target position based on velocity
            predictedX := 0.0
            predictedY := 0.0
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
            baseSpeed := baseSpeed * 0.7
        else if (distance > 200)
            baseSpeed := baseSpeed * 0.85
        
        ; Adjust speed based on consecutive hits
        if (this.consecutiveHits > 5)
            baseSpeed := baseSpeed * 1.2
        else if (this.consecutiveHits > 2)
            baseSpeed := baseSpeed * 1.1
            
        ; Ensure speed stays within reasonable bounds
        if (baseSpeed < 0.5)
            baseSpeed := 0.5
        if (baseSpeed > 1.5)
            baseSpeed := 1.5
            
        return baseSpeed
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