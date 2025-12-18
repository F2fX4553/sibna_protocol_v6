import os
import sys
import time
import threading
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.theme import Theme

# Mocking the sibna import if not installed, but in a real scenario, this would be:
# from sibna import SecureContext, Config
try:
    from sibna import SecureContext, Config
except ImportError:
    # Fallback for demonstration if the binary isn't built yet
    class Config:
        def __init__(self, **kwargs): pass
    class SecureContext:
        def __init__(self, config, password=None): pass
        def load_identity(self, ed_pub, x_pub, seed): pass
        def encrypt_message(self, peer_id, message): return b"encrypted_blob"
        def decrypt_message(self, peer_id, ciphertext): return b"decrypted message"
        def perform_handshake(self, peer_id, initiator, peer_ik, peer_spk): pass

custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
})

console = Console(theme=custom_theme)

class SibnaCLI:
    def __init__(self):
        self.messages = []
        self.running = True
        self.peer_id = "Peer_B"
        self.my_id = "Alice"
        
        # Initialize Sibna
        config = Config(max_skipped_messages=1000)
        self.ctx = SecureContext(config, password=b"demo_pass")
        # In a real app, identity would be loaded from disk/server
        
    def add_message(self, sender, text):
        self.messages.append({"sender": sender, "text": text, "time": time.strftime("%H:%M:%S")})
        if len(self.messages) > 15:
            self.messages.pop(0)

    def make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="sidebar", ratio=1),
            Layout(name="chat", ratio=3),
        )
        return layout

    def update_display(self, layout):
        # Header
        layout["header"].update(Panel(Text(f"Sibna Secure Messenger - Logged in as {self.my_id}", justify="center", style="bold white on blue")))
        
        # Sidebar (Contacts)
        table = Table(show_header=False, box=None)
        table.add_row(Text(f"• {self.peer_id}", style="success"))
        table.add_row(Text("  System Status: Online", style="info"))
        layout["sidebar"].update(Panel(table, title="Contacts", border_style="blue"))
        
        # Chat Window
        chat_table = Table(show_header=False, expand=True, box=None)
        for msg in self.messages:
            style = "bold green" if msg["sender"] == self.my_id else "bold yellow"
            chat_table.add_row(f"[{msg['time']}] {msg['sender']}: {msg['text']}", style=style)
        
        layout["chat"].update(Panel(chat_table, title=f"Chatting with {self.peer_id}", border_style="cyan"))
        
        # Footer
        layout["footer"].update(Panel("Type your message and press Enter (Type '/exit' to quit)", style="dim"))

    def run(self):
        layout = self.make_layout()
        
        # Simulate incoming messages
        def simulate_incoming():
            time.sleep(5)
            self.add_message(self.peer_id, "Hello! This is a secure transmission via Sibna Protocol.")
            time.sleep(10)
            self.add_message(self.peer_id, "The Double Ratchet is successfully rotating keys.")

        threading.Thread(target=simulate_incoming, daemon=True).start()

        with Live(layout, refresh_per_second=4, screen=True) as live:
            while self.running:
                self.update_display(layout)
                # Note: Live display with Prompt is tricky in some consoles
                # Here we use a separate input mechanism or just simulate for the example
                try:
                    msg_text = Prompt.ask("> ", console=console)
                    if msg_text.lower() == "/exit":
                        self.running = False
                    else:
                        # Encryption happens here
                        # encrypted = self.ctx.encrypt_message(self.peer_id, msg_text.encode())
                        self.add_message(self.my_id, msg_text)
                except EOFError:
                    break

if __name__ == "__main__":
    app = SibnaCLI()
    app.run()
