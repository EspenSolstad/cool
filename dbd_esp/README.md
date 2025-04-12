# Dead by Daylight Python ESP

A high-performance, stealth-optimized ESP hack for Dead by Daylight written in Python. This version uses advanced memory manipulation techniques and process hiding to provide a smooth, undetectable wallhack experience.

## Advanced Features

### Core Functionality
- Player ESP (Survivors and Killer)
- Health status indicators
- Item tracking
- Carried state detection
- Transparent DirectX overlay

### Performance Optimizations
- Memory batch reading (4KB chunks)
- Smart caching system
- Thread suspension during critical operations
- Dynamic update rate adjustment
- Automatic performance tuning

### Stealth Measures
- Process hiding in system services
- Memory access pattern randomization
- Thread priority manipulation
- Steam/EAC timing optimization
- DLL hijacking prevention

## Requirements

- Windows 10/11 (64-bit)
- Python 3.8 or higher
- Administrator privileges
- Dead by Daylight game

## Quick Start

### Easy Installation
1. Right-click `install.bat` and run as Administrator
2. Wait for the installation to complete
3. Right-click `build.bat` and run as Administrator
4. Choose whether to run the ESP immediately

### Manual Installation
```bash
# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Build executable
pyinstaller --noconfirm --onefile --noconsole run.py
```

## Usage Guide

### Optimal Launch Order
1. Start Steam
2. Wait for Steam to fully initialize
3. Run the ESP executable as Administrator
4. Launch Dead by Daylight
5. ESP will automatically attach when game starts

### Performance Settings
The ESP automatically tunes itself based on your system:
- Update rate: 60-120 FPS
- Memory batch size: 4-16 KB
- Cache size: Up to 1024 pages
- Thread priorities: Update thread HIGH, Render thread NORMAL

### Controls
- ESC: Exit ESP
- Minimize the console window while playing

## Visual Features

### Survivor ESP
- Green Box: Healthy survivor
- Yellow Box: Injured survivor
- Gray Box: Dying state
- Orange Box: Being carried
- Shows equipped items with status

### Killer ESP
- Red Box: Killer location
- Always visible through walls
- Includes terror radius indicator

## Advanced Anti-Detection

1. Process Protection
   - Hides in system services
   - Randomized process names
   - PEB manipulation
   - Thread state management

2. Memory Operations
   - Batch reading to reduce API calls
   - Random delays between operations
   - Smart caching to avoid patterns
   - Thread suspension during critical reads

3. Launch Timing
   - Waits for proper Steam initialization
   - Monitors EAC startup sequence
   - Attaches during optimal windows

## Performance Tuning

The ESP includes automatic performance tuning:
- Dynamically adjusts update rates
- Scales batch sizes based on system load
- Cleans memory cache periodically
- Optimizes thread priorities
- Suspends unnecessary game threads

## Troubleshooting

### Common Issues

1. "Failed to attach to game process"
   - Verify Steam is fully initialized
   - Run as Administrator
   - Check antivirus exclusions
   - Try restarting Steam completely

2. "Game window not found"
   - Ensure game is in borderless or windowed mode
   - Check Windows display scaling settings
   - Verify no other overlays are blocking

3. Performance Issues
   - Close unnecessary background programs
   - Set game to high priority
   - Reduce game graphics settings
   - Check Windows power plan

### Performance Optimization

If experiencing lag:
1. Close background applications
2. Set Dead by Daylight process priority to High
3. Ensure Windows Game Mode is disabled
4. Update graphics drivers
5. Run Windows in Performance mode

## Security Notes

- The ESP uses usermode-only operations
- No kernel drivers or system modifications
- Cleans up all traces on exit
- Prevents multiple instances
- Avoids common detection patterns

## Important Warnings

- Use at your own risk! Cheating can result in game bans
- Always run as Administrator
- Keep the console window minimized
- Close ESP before exiting game
- Some features may break after game updates
- Do not share your executable with others

## Technical Details

### Memory Management
- Page-aligned reads
- Smart caching system
- Batch operations
- Thread state control

### Process Protection
- PEB manipulation
- Service disguise
- API call randomization
- DLL path protection

## Credits

Based on the original C++ version but completely rewritten in Python with significant improvements in performance, stealth, and reliability.

## Disclaimer

This project is for educational purposes only. Use at your own risk. The authors are not responsible for any bans or other consequences of using this software.
