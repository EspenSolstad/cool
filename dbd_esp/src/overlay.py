import pygame
import win32gui
import win32con
import win32api
from typing import List, Tuple, Optional
import math
from .entity import Entity, Vector3

class Overlay:
    def __init__(self):
        pygame.init()
        
        # Get game window
        self.game_hwnd = win32gui.FindWindow("DeadByDaylight", None)
        if not self.game_hwnd:
            raise Exception("Game window not found")
            
        # Get window dimensions
        self.window_rect = win32gui.GetWindowRect(self.game_hwnd)
        self.width = self.window_rect[2] - self.window_rect[0]
        self.height = self.window_rect[3] - self.window_rect[1]
        
        # Create transparent overlay window
        self.screen = pygame.display.set_mode((self.width, self.height), pygame.NOFRAME)
        pygame.display.set_caption("Overlay")
        
        # Set window properties
        hwnd = win32gui.GetForegroundWindow()
        win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE,
            win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) | win32con.WS_EX_LAYERED | win32con.WS_EX_TRANSPARENT)
        win32gui.SetLayeredWindowAttributes(hwnd, win32api.RGB(0,0,0), 0, win32con.LWA_COLORKEY)
        
        # Make window always on top
        win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0,
            win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
            
        # Font setup
        self.font = pygame.font.SysFont('Arial', 14)
        self.font_height = self.font.get_height()
        
    def world_to_screen(self, pos: Vector3) -> Optional[Tuple[int, int]]:
        """Convert 3D world coordinates to 2D screen coordinates"""
        try:
            # Basic perspective projection
            screen_x = (pos.x / pos.z) * self.width + self.width/2
            screen_y = (pos.y / pos.z) * self.height + self.height/2
            
            # Check if point is on screen
            if 0 <= screen_x <= self.width and 0 <= screen_y <= self.height:
                return (int(screen_x), int(screen_y))
            return None
        except:
            return None
            
    def draw_box(self, pos: Tuple[int, int], width: int, height: int, color: Tuple[int, int, int], thickness: int = 2):
        """Draw a box on screen"""
        x, y = pos
        
        # Draw box corners
        pygame.draw.line(self.screen, color, (x - width//2, y - height//2),
                        (x + width//2, y - height//2), thickness)
        pygame.draw.line(self.screen, color, (x + width//2, y - height//2),
                        (x + width//2, y + height//2), thickness)
        pygame.draw.line(self.screen, color, (x + width//2, y + height//2),
                        (x - width//2, y + height//2), thickness)
        pygame.draw.line(self.screen, color, (x - width//2, y + height//2),
                        (x - width//2, y - height//2), thickness)
                        
    def draw_health_bar(self, pos: Tuple[int, int], health: int, width: int = 50, height: int = 5):
        """Draw health bar"""
        x, y = pos
        
        # Background (empty health bar)
        pygame.draw.rect(self.screen, (255, 0, 0),
                        (x - width//2, y - height//2, width, height))
        
        # Foreground (filled health bar)
        if health > 0:
            fill_width = int(width * (health / 100))
            pygame.draw.rect(self.screen, (0, 255, 0),
                           (x - width//2, y - height//2, fill_width, height))
                           
    def draw_text(self, pos: Tuple[int, int], text: str, color: Tuple[int, int, int]):
        """Draw text with background"""
        x, y = pos
        
        # Render text
        text_surface = self.font.render(text, True, color)
        text_rect = text_surface.get_rect()
        text_rect.center = (x, y)
        
        # Draw text
        self.screen.blit(text_surface, text_rect)
        
    def render(self, entities: List[Entity]) -> None:
        """Render all entities"""
        # Update window position to match game window
        game_rect = win32gui.GetWindowRect(self.game_hwnd)
        hwnd = win32gui.GetForegroundWindow()
        win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST,
                            game_rect[0], game_rect[1], 0, 0,
                            win32con.SWP_NOSIZE)
        
        # Clear screen with transparency
        self.screen.fill((0,0,0))
        
        # Draw entities
        for entity in entities:
            # Convert world position to screen coordinates
            screen_pos = self.world_to_screen(entity.position)
            if not screen_pos:
                continue
                
            # Draw box around entity
            self.draw_box(screen_pos, 40, 80, entity.color)
            
            # Draw health bar if not killer
            if not entity.is_killer:
                health_pos = (screen_pos[0], screen_pos[1] + 50)
                self.draw_health_bar(health_pos, entity.health)
            
            # Draw name and info
            name_pos = (screen_pos[0], screen_pos[1] - 50)
            self.draw_text(name_pos, entity.name, entity.color)
            
            if entity.item_name != "None":
                item_pos = (screen_pos[0], screen_pos[1] - 35)
                self.draw_text(item_pos, f"Item: {entity.item_name}", (255, 255, 255))
                
        # Update display
        pygame.display.flip()
        
    def handle_events(self) -> bool:
        """Handle window events, return False if should close"""
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return False
        return True
        
    def cleanup(self):
        """Clean up resources"""
        pygame.quit()
