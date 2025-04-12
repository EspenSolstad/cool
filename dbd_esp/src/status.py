import os
import time
import threading
import keyboard
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import psutil
from .entity import Entity

class StatusDisplay:
    def __init__(self):
        self.settings = {
            'esp_enabled': True,
            'show_items': True,
            'show_health': True,
            'show_distance': True,
            'performance_mode': False,
            'killer_color': 'RED',
            'survivor_color': 'GREEN',
            'injured_color': 'YELLOW',
            'dying_color': 'GRAY',
            'carried_color': 'ORANGE',
            'box_thickness': 2,
            'text_size': 14,
            'refresh_rate': 60
        }
        
        self.color_options = ['RED', 'GREEN', 'BLUE', 'YELLOW', 'PURPLE', 'CYAN', 'WHITE']
        self.current_color_index = 0
        self.start_time = datetime.now()
        self.status_file = "dbd_status.txt"
        self.running = False
        self.last_entities: List[Entity] = []
        
    def start(self):
        """Start the status display system"""
        self.running = True
        
        # Register hotkeys
        keyboard.on_press_key('f1', lambda _: self.toggle_setting('esp_enabled'))
        keyboard.on_press_key('f2', lambda _: self.toggle_setting('show_items'))
        keyboard.on_press_key('f3', lambda _: self.toggle_setting('show_health'))
        keyboard.on_press_key('f4', lambda _: self.toggle_setting('show_distance'))
        keyboard.on_press_key('f5', lambda _: self.toggle_setting('performance_mode'))
        keyboard.on_press_key('f6', lambda _: self.cycle_killer_color())
        keyboard.on_press_key('f7', lambda _: self.adjust_value('box_thickness', 1))
        keyboard.on_press_key('f8', lambda _: self.adjust_value('box_thickness', -1))
        keyboard.on_press_key('f9', lambda _: self.adjust_value('text_size', 1))
        keyboard.on_press_key('f10', lambda _: self.adjust_value('text_size', -1))
        
        # Start update thread
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
    def stop(self):
        """Stop the status display system"""
        self.running = False
        if os.path.exists(self.status_file):
            try:
                os.remove(self.status_file)
            except:
                pass
                
    def toggle_setting(self, setting: str):
        """Toggle a boolean setting"""
        if setting in self.settings:
            self.settings[setting] = not self.settings[setting]
            
    def cycle_killer_color(self):
        """Cycle through available killer colors"""
        self.current_color_index = (self.current_color_index + 1) % len(self.color_options)
        self.settings['killer_color'] = self.color_options[self.current_color_index]
        
    def adjust_value(self, setting: str, delta: int):
        """Adjust a numeric setting"""
        if setting in self.settings:
            if setting == 'box_thickness':
                self.settings[setting] = max(1, min(5, self.settings[setting] + delta))
            elif setting == 'text_size':
                self.settings[setting] = max(8, min(24, self.settings[setting] + delta))
                
    def update_entities(self, entities: List[Entity]):
        """Update the list of current entities"""
        self.last_entities = entities
        
    def _format_distance(self, distance: float) -> str:
        """Format distance with direction"""
        if not self.settings['show_distance']:
            return ""
        directions = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
        # TODO: Calculate actual direction based on player orientation
        direction = directions[0]  # Placeholder
        return f"({distance:.0f}m {direction})"
        
    def _format_uptime(self) -> str:
        """Format the ESP uptime"""
        delta = datetime.now() - self.start_time
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        seconds = delta.seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
    def _get_memory_usage(self) -> str:
        """Get current memory usage"""
        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024
        return f"{memory_mb:.1f}MB"
        
    def _update_loop(self):
        """Main update loop for status file"""
        while self.running:
            try:
                # Build status text
                status = []
                status.append("=== DBD ESP CONTROL PANEL ===")
                status.append(f"[F1] Toggle ESP: {'ENABLED' if self.settings['esp_enabled'] else 'DISABLED'}")
                status.append(f"[F2] Show Items: {'ENABLED' if self.settings['show_items'] else 'DISABLED'}")
                status.append(f"[F3] Show Health: {'ENABLED' if self.settings['show_health'] else 'DISABLED'}")
                status.append(f"[F4] Distance Display: {'ENABLED' if self.settings['show_distance'] else 'DISABLED'}")
                status.append(f"[F5] Performance Mode: {'ENABLED' if self.settings['performance_mode'] else 'DISABLED'}")
                status.append(f"[F6] Killer Color: {self.settings['killer_color']}")
                status.append(f"[F7/F8] Box Thickness: {self.settings['box_thickness']}")
                status.append(f"[F9/F10] Text Size: {self.settings['text_size']}")
                status.append("")
                
                # Active players section
                status.append("-- ACTIVE PLAYERS --")
                for entity in self.last_entities:
                    if entity.is_killer:
                        status.append(f"KILLER: {self._format_distance(50)}")  # TODO: Calculate actual distance
                    else:
                        health_status = "HEALTHY"
                        if entity.health <= 0:
                            health_status = "DYING"
                        elif entity.health <= 50:
                            health_status = "INJURED"
                        elif entity.being_carried:
                            health_status = "CARRIED"
                            
                        item_text = f" - {entity.item_name}" if entity.item_name != "None" and self.settings['show_items'] else ""
                        health_text = f" - {health_status}" if self.settings['show_health'] else ""
                        distance_text = f" {self._format_distance(50)}" if self.settings['show_distance'] else ""  # TODO: Calculate actual distance
                        
                        status.append(f"Survivor{item_text}{health_text}{distance_text}")
                        
                status.append("")
                
                # Statistics section
                status.append("-- STATISTICS --")
                status.append(f"Memory Usage: {self._get_memory_usage()}")
                status.append(f"Refresh Rate: {self.settings['refresh_rate']} FPS")
                status.append(f"Uptime: {self._format_uptime()}")
                
                # Write to file
                with open(self.status_file, 'w') as f:
                    f.write('\n'.join(status))
                    
                # Sleep based on performance mode
                if self.settings['performance_mode']:
                    time.sleep(0.1)  # 10 FPS in performance mode
                else:
                    time.sleep(0.016)  # ~60 FPS normally
                    
            except Exception as e:
                print(f"Status update error: {e}")
                time.sleep(1)  # Avoid spam on error
