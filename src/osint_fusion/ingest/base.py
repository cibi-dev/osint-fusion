"""Clase base para conectores de fuentes OSINT y validación de seguridad SSRF (CWE-918)."""

from __future__ import annotations

from abc import ABC, abstractmethod
import ipaddress
import socket
from urllib.parse import urlparse

from osint_fusion.schemas import OSINTDocument


def validate_target_url_ssrf(url: str) -> bool:
    """Verifica que una URL sea pública y segura, bloqueando vectores SSRF (CWE-918).

    Bloquea:
    - Esquemas no HTTP/HTTPS (file://, gopher://, ftp://, etc.)
    - Direcciones de loopback (127.0.0.1, ::1)
    - Bloques privados RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Direcciones link-local (169.254.0.0/16)
    - Metadatos de proveedores cloud (169.254.169.254)

    Args:
        url: URL a verificar antes de realizar una conexión de red.

    Returns:
        True si la URL es segura y apunta a un destino público; False en caso contrario.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Comprobar si el hostname es una IP literal
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False
            return True
        except ValueError:
            pass  # Es un nombre de dominio (FQDN)

        # Resolver el dominio a IP para verificar si resuelve a red privada
        try:
            resolved_ip_str = socket.gethostbyname(hostname)
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_reserved:
                return False
        except (socket.gaierror, UnicodeError):
            # No se pudo resolver en este momento; si el nombre es 'localhost' bloquear
            if hostname.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
                return False

        return True
    except Exception:
        return False


class BaseConnector(ABC):
    """Interfaz abstracta para conectores de ingesta de inteligencia criminal y ciberamenazas."""

    def __init__(self, name: str, source_uri: str) -> None:
        self.name = name
        self.source_uri = source_uri

    @abstractmethod
    def fetch_documents(self) -> list[OSINTDocument]:
        """Obtiene y transforma los datos de la fuente en documentos estructurados OSINTDocument."""
        pass
