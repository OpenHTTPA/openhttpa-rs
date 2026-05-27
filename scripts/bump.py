# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "rich",
#     "questionary",
# ]
# ///

import os
import sys
import re
from rich.console import Console
from rich.panel import Panel
import questionary

console = Console()

def parse_version(v_str):
    parts = v_str.split('.')
    return [int(p) for p in parts]

def bump_version(v_str, bump_type):
    parts = parse_version(v_str)
    if bump_type == "patch":
        parts[2] += 1
    elif bump_type == "minor":
        parts[1] += 1
        parts[2] = 0
    elif bump_type == "major":
        parts[0] += 1
        parts[1] = 0
        parts[2] = 0
    return ".".join(map(str, parts))

def main():
    console.print(Panel.fit("[bold blue]📦 OpenHTTPA Semantic Version Bumper[/bold blue]"))
    
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cargo_toml_path = os.path.join(workspace_root, "Cargo.toml")
    
    with open(cargo_toml_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Find current version
    match = re.search(r'\[workspace\.package\][^\[]*?\bversion\s*=\s*"([^"]+)"', content)
    if not match:
        console.print("[red]Could not find workspace version in Cargo.toml[/red]")
        sys.exit(1)
        
    current_version = match.group(1)
    
    patch_v = bump_version(current_version, "patch")
    minor_v = bump_version(current_version, "minor")
    major_v = bump_version(current_version, "major")
    
    choices = [
        f"Patch ({current_version} -> {patch_v})",
        f"Minor ({current_version} -> {minor_v})",
        f"Major ({current_version} -> {major_v})",
        "Custom"
    ]
    
    bump_choice = questionary.select(
        f"Current version is {current_version}. Select bump type:",
        choices=choices
    ).ask()
    
    if not bump_choice:
        sys.exit(0)
        
    if bump_choice.startswith("Patch"):
        new_version = patch_v
    elif bump_choice.startswith("Minor"):
        new_version = minor_v
    elif bump_choice.startswith("Major"):
        new_version = major_v
    else:
        new_version = questionary.text("Enter new version (e.g. 1.2.3):").ask()
        if not new_version:
            sys.exit(0)
            
    # Verify the new version format
    if not re.match(r"^\d+\.\d+\.\d+(?:-.+)?$", new_version):
        console.print(f"[red]Invalid semver format: {new_version}[/red]")
        sys.exit(1)
        
    confirm = questionary.confirm(f"Bump version from {current_version} to {new_version} across the repository?").ask()
    if not confirm:
        sys.exit(0)
        
    files_to_update = [
        ("Cargo.toml", f'version = "{current_version}"', f'version = "{new_version}"'),
        ("package.json", f'"version": "{current_version}"', f'"version": "{new_version}"'),
        ("bindings/nodejs/package.json", f'"version": "{current_version}"', f'"version": "{new_version}"'),
        ("bindings/python/pyproject.toml", f'version = "{current_version}"', f'version = "{new_version}"'),
        ("crates/openhttpa-tee/Cargo.toml", f'version = "{current_version}"', f'version = "{new_version}"'),
    ]
    
    # Regex to handle arbitrary spacing in Cargo.toml `version     = "0.1.1"`
    cargo_regex = re.compile(r'version\s*=\s*"' + re.escape(current_version) + r'"')
    json_regex = re.compile(r'"version"\s*:\s*"' + re.escape(current_version) + r'"')
    
    for relative_path, old_str, new_str in files_to_update:
        filepath = os.path.join(workspace_root, relative_path)
        if not os.path.exists(filepath):
            continue
            
        with open(filepath, "r", encoding="utf-8") as f:
            file_content = f.read()
            
        if filepath.endswith(".toml"):
            new_content = cargo_regex.sub(f'version = "{new_version}"', file_content)
        elif filepath.endswith(".json"):
            new_content = json_regex.sub(f'"version": "{new_version}"', file_content)
        else:
            new_content = file_content.replace(old_str, new_str)
            
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
            
        console.print(f"[bold green]✓ Updated {relative_path}[/bold green]")
        
    console.print("\n[bold cyan]Run the following to update lockfiles:[/bold cyan]")
    console.print("  cargo check")
    console.print("  pnpm install")
    console.print(f"\n[bold green]🎉 Version successfully bumped to {new_version}![/bold green]")

if __name__ == "__main__":
    main()
