import os
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def generate_identity_report(user_id):
    """
    Simulates a professional identity report that a developer would use
    to debug or manage user keys.
    """
    console.print(Panel(f"[bold blue]Identity Management Tool[/bold blue]\n[dim]User: {user_id}[/dim]", expand=False))
    
    # Mock data
    data = {
        "identity_key_pub": "ed25519:v1:7f8a...92b1",
        "signed_prekey_pub": "x25519:v1:33a1...bb02",
        "onetime_prekeys_remaining": 48,
        "last_rotated": "2023-10-25 14:20:00",
        "storage_mode": "Sled Encrypted",
        "db_integrity": "OK"
    }
    
    table = Table(title="Security Parameters", header_style="bold magenta")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    
    for key, value in data.items():
        table.add_row(key.replace("_", " ").title(), str(value))
        
    console.print(table)
    
    console.print("\n[yellow]Recommended Actions:[/yellow]")
    console.print("- [x] Periodic PreKey rotation needed in 4 days.")
    console.print("- [ ] Backup Identity Seed to offline storage.")

def export_public_bundle(user_id):
    bundle = {
        "user_id": user_id,
        "ik": "base64_blob_...",
        "spk": "base64_blob_...",
        "spk_sig": "base64_blob_...",
        "opks": ["blob1", "blob2", "blob3"]
    }
    file_name = f"{user_id}_bundle.json"
    with open(file_name, "w") as f:
        json.dump(bundle, f, indent=4)
    console.print(f"\n[green]✅ Exported public bundle to {file_name}[/green]")

if __name__ == "__main__":
    generate_identity_report("Alice_Dev")
    export_public_bundle("Alice_Dev")
