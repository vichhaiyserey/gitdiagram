"""secdiagram: deterministic architecture and security graphs for Python, .NET, Node.js, and polyglot repositories."""

__version__ = "0.2.0"
SCHEMA_VERSION = 1

from .config import SecdiagramConfig, load_config
from .high_level import (
    HighLevelArchitecture,
    Subsystem,
    SubsystemConnection,
    build_high_level_architecture,
    render_mermaid_highlevel,
)
from .render_image import ImageRenderError, render_image
from .server import BasicAuthenticator, NoOpAuthenticator, create_server, serve

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "render_image",
    "ImageRenderError",
    "HighLevelArchitecture",
    "Subsystem",
    "SubsystemConnection",
    "build_high_level_architecture",
    "render_mermaid_highlevel",
    "create_server",
    "serve",
    "load_config",
    "SecdiagramConfig",
    "BasicAuthenticator",
    "NoOpAuthenticator",
]
