# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "rich",
#     "questionary",
# ]
# ///

import os
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
import questionary

console = Console()

SCRIPTS = {
    "Crates (Rust workspace)": "publish_crates.sh",
    "Python Bindings": "publish_python.sh",
    "Node.js (NPM) Bindings": "publish_npm.sh",
    "WASM Bindings": "publish_wasm.sh",
    "Go FFI Module": "publish_go.sh",
    "GitHub Release": "publish_github.sh",
}

TOKEN_REQS = {
    "publish_crates.sh": ["CARGO_REGISTRY_TOKEN"],
    "publish_python.sh": ["PYPI_TOKEN"],
    "publish_npm.sh": ["NPM_TOKEN", "GITHUB_TOKEN"],
    "publish_wasm.sh": ["NPM_TOKEN", "GITHUB_TOKEN"],
    "publish_github.sh": ["GITHUB_TOKEN"],
    "publish_go.sh": [],
}

def main():
    console.print(Panel.fit("[bold blue]🚀 OpenHTTPA Interactive Publish Wizard[/bold blue]"))
    
    selected_targets = questionary.checkbox(
        "Select the packages to publish:",
        choices=list(SCRIPTS.keys())
    ).ask()
    
    if not selected_targets:
        console.print("[yellow]No targets selected. Exiting.[/yellow]")
        sys.exit(0)
    
    is_dry_run = questionary.confirm("Run in DRY-RUN mode? (Recommended first)", default=True).ask()
    
    # Collect required tokens for selected targets
    required_tokens = set()
    for target in selected_targets:
        script = SCRIPTS[target]
        for t in TOKEN_REQS[script]:
            required_tokens.add(t)
            
    env = os.environ.copy()
    env["DRY_RUN"] = "1" if is_dry_run else "0"
    
    # Collect credentials if they aren't already set
    for token in required_tokens:
        if not env.get(token):
            # GitHub token is sometimes optional (for NPM/WASM) but required for GitHub release
            is_optional = token == "GITHUB_TOKEN" and "publish_github.sh" not in [SCRIPTS[t] for t in selected_targets]
            
            prompt_msg = f"Enter {token}{' (Optional)' if is_optional else ''}:"
            
            # Use questionary.password to hide the input
            val = questionary.password(prompt_msg).ask()
            
            if val:
                env[token] = val
            elif not is_optional and not is_dry_run:
                # We only hard-fail if not dry-run and not optional, 
                # as dry-runs often don't need tokens, but we ask just in case.
                console.print(f"[red]Error: {token} is required for a production publish.[/red]")
                sys.exit(1)
                    
    console.print(f"\n[bold green]Starting publish operations... (Dry Run: {is_dry_run})[/bold green]")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    for target in selected_targets:
        script = SCRIPTS[target]
        script_path = os.path.join(script_dir, script)
        console.print(f"\n[bold cyan]==> Running {target} ({script})[/bold cyan]")
        
        try:
            subprocess.run(["bash", script_path], env=env, check=True)
            console.print(f"[bold green]✓ {target} finished successfully.[/bold green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]✗ {target} failed with exit code {e.returncode}.[/bold red]")
            should_continue = questionary.confirm("Continue with remaining packages?", default=False).ask()
            if not should_continue:
                sys.exit(e.returncode)

    console.print("\n[bold green]🎉 All selected publish operations completed![/bold green]")

if __name__ == "__main__":
    main()
