import typer
from osint_fusion import __version__

app = typer.Typer(name="osint-fusion", help="OSINT Intelligence Fusion CLI")

@app.command()
def version():
    typer.echo(f"osint-fusion v{__version__}")

if __name__ == "__main__":
    app()
