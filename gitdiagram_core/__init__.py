"""gitdiagram: deterministic architecture and security graphs for Python, .NET, Node.js, and polyglot repositories."""

__version__ = "0.1.0"
SCHEMA_VERSION = 1

from .high_level import (
    HighLevelArchitecture,
    Subsystem,
    SubsystemConnection,
    build_high_level_architecture,
    render_mermaid_highlevel,
)
from .render_image import ImageRenderError, render_image

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
]
