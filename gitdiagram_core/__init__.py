"""gitdiagram: deterministic architecture and security graphs for Python repositories."""

from .render_image import ImageRenderError, render_image

__version__ = "0.1.0"
SCHEMA_VERSION = 1

__all__ = ["__version__", "SCHEMA_VERSION", "render_image", "ImageRenderError"]
