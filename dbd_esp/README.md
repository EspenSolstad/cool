# Dead by Daylight Python ESP

A usermode ESP hack for Dead by Daylight written in Python. This version avoids kernel-level operations to bypass driver signature enforcement issues while maintaining core ESP functionality.

## Features

- Player ESP (Survivors and Killer)
- Health status indicators
- Item tracking
- Carried state detection
- Transparent overlay
- Anti-detection measures
  - Randomized memory read delays
  - Process name randomization
  - Minimal CPU/memory footprint

## Requirements

- Python 3.8 or higher
- Windows 10/11
- Administrator privileges
- Dead by Daylight game

## Installation

1. Clone or download this repository
2. Open a command prompt as Administrator
3. Navigate to the project directory
4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Launch Dead by Daylight
2. Run the ESP as Administrator:
```bash
python run.py
```

### Controls
- ESC: Exit ESP
- Minimize the console window while playing

## Features Explained

### Survivor ESP
- Green Box: Healthy survivor
- Yellow Box: Injured survivor
- Gray Box: Dying state
- Orange Box: Being carried
- Shows equipped items

### Killer ESP
- Red Box: Killer location
- Always visible through walls

## Anti-Detection Features

This ESP implements several measures to reduce detection risk:

1. Usermode-only operation (no kernel drivers)
2. Randomized memory read patterns
3. Minimal API calls
4. Process name randomization
5. Random delays between updates

## Important Notes

- Use at your own risk! Cheating can result in game bans
- Run both the game and ESP as Administrator
- Keep the console window minimized while playing
- Close the ESP before closing the game
- Some features may break after game updates due to offset changes

## Troubleshooting

1. "Failed to attach to game process"
   - Make sure DBD is running
   - Run as Administrator
   - Check antivirus isn't blocking the ESP

2. "Game window not found"
   - Make sure DBD is in focus
   - Try restarting the ESP

3. ESP not showing
   - Verify game is in windowed or borderless mode
   - Check if overlays are enabled in Windows

## Credits

Based on the original C++ version but rewritten in Python for better accessibility and to avoid kernel driver issues.

## Disclaimer

This project is for educational purposes only. Use at your own risk. The authors are not responsible for any bans or other consequences of using this software.
