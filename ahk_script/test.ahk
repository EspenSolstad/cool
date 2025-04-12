#NoEnv
#SingleInstance Force
#Persistent

; Basic test variables
testVar := 0.0

; Basic hotkey test
$*F1::
    MsgBox, Test script is working!
    testVar := testVar + 1.0
    MsgBox, Counter: %testVar%
return

; Exit script
$*End::ExitApp

MsgBox, Test script loaded! Press F1 to test, End to exit.
