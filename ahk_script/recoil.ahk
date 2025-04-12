#Include %A_ScriptDir%\utils.ahk

; Recoil compensation system
class RecoilCompensation {
    ; Initialize recoil compensation system
    __New() {
        this.recoilSamples := []
        this.lastCrosshairPos := {x: 0, y: 0}
        this.isCompensating := false
        this.sampleCount := 0
        this.lastSampleTime := 0
        
        ; Initialize moving averages for smoothing
        this.movingAvgX := 0
        this.movingAvgY := 0
    }
    
    ; Start recoil compensation
    StartCompensation() {
        this.isCompensating := true
        this.sampleCount := 0
        this.recoilSamples := []
        
        ; Get initial crosshair position
        mousePos := GetMousePos()
        this.lastCrosshairPos := mousePos
        this.lastSampleTime := A_TickCount
    }
    
    ; Stop recoil compensation
    StopCompensation() {
        this.isCompensating := false
    }
    
    ; Sample current recoil and return compensation values
    SampleRecoil() {
        if (!this.isCompensating)
            return {x: 0, y: 0}
            
        currentTime := A_TickCount
        if (currentTime - this.lastSampleTime < RecoilConfig.SampleRate)
            return {x: this.movingAvgX, y: this.movingAvgY}
            
        ; Get current mouse position
        currentPos := GetMousePos()
        
        ; Calculate recoil vector
        recoilVector := CalculateMovementVector(
            this.lastCrosshairPos.x, this.lastCrosshairPos.y,
            currentPos.x, currentPos.y
        )
        
        ; Store recoil sample
        if (this.sampleCount < RecoilConfig.MaxSamples) {
            this.recoilSamples.Push({
                x: recoilVector.x,
                y: recoilVector.y,
                time: currentTime
            })
            this.sampleCount++
        } else {
            ; Remove oldest sample and add new one
            this.recoilSamples.RemoveAt(1)
            this.recoilSamples.Push({
                x: recoilVector.x,
                y: recoilVector.y,
                time: currentTime
            })
        }
        
        ; Calculate compensation values using exponential smoothing
        compensationX := 0
        compensationY := 0
        
        ; Weight recent samples more heavily
        sampleWeight := 1.0
        totalWeight := 0
        
        for i, sample in this.recoilSamples {
            compensationX += (sample.x * sampleWeight)
            compensationY += (sample.y * sampleWeight)
            totalWeight += sampleWeight
            sampleWeight *= 0.9  ; Decay weight for older samples
        }
        
        ; Calculate weighted average
        if (totalWeight > 0) {
            compensationX /= totalWeight
            compensationY /= totalWeight
        }
        
        ; Apply smoothing to compensation values
        this.movingAvgX := ExponentialSmooth(this.movingAvgX, -compensationX, RecoilConfig.SmoothingFactor)
        this.movingAvgY := ExponentialSmooth(this.movingAvgY, -compensationY, RecoilConfig.SmoothingFactor)
        
        ; Update last position and time
        this.lastCrosshairPos := currentPos
        this.lastSampleTime := currentTime
        
        return {
            x: this.movingAvgX,
            y: this.movingAvgY
        }
    }
    
    ; Apply recoil compensation
    CompensateRecoil() {
        if (!this.isCompensating)
            return
            
        compensation := this.SampleRecoil()
        
        ; Apply compensation if significant movement detected
        if (Abs(compensation.x) > 0.5 || Abs(compensation.y) > 0.5) {
            DllCall("mouse_event", "UInt", 0x01, 
                    "Int", Round(compensation.x), 
                    "Int", Round(compensation.y), 
                    "UInt", 0, "Int", 0)
        }
    }
}

; Create global recoil compensation instance
global RecoilCompensator := new RecoilCompensation()
