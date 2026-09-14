"""Submódulo API REST FastAPI para OSINT Fusion."""

from osint_fusion.api.app import app, create_app

__all__ = ["app", "create_app"]
