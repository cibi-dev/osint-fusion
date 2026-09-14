"""Instancia principal de la aplicación FastAPI OSINT Fusion."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from osint_fusion.api.routes import router


def create_app() -> FastAPI:
    """Crea y configura la aplicación FastAPI para el motor OSINT Fusion."""
    app = FastAPI(
        title="OSINT Fusion Engine API",
        description=(
            "Plataforma de inteligencia de fuentes abiertas, deduplicación sublineal MinHash/LSH, "
            "análisis de grafos de amenazas NetworkX y detección de anillos de fraude."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Middleware CORS seguro
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
