"""Render Mermaid diagrams to image formats (PNG, SVG, PDF)."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zlib
from pathlib import Path


class ImageRenderError(RuntimeError):
    """Raised when Mermaid diagram cannot be rendered to an image."""

    pass


def sanitize_mermaid(source: str) -> str:
    """Ensure mermaid syntax doesn't contain known parser-breaking keywords."""
    # Mermaid parsers break on `:::class` and `classDef class ` because `class` is a statement keyword.
    cleaned = source.replace(":::class", ":::cls")
    cleaned = cleaned.replace("classDef class ", "classDef cls ")
    return cleaned


def render_local_mmdc(
    source: str,
    output_path: Path,
    image_format: str = "png",
    timeout: float = 60.0,
) -> None:
    """Render Mermaid source using local mermaid-cli (mmdc)."""
    mmdc = shutil.which("mmdc")
    if not mmdc:
        raise ImageRenderError(
            "Local Mermaid CLI ('mmdc') was not found on PATH. "
            "Install it globally with 'npm install -g @mermaid-js/mermaid-cli' "
            "or use provider 'auto' / 'kroki'."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".mmd", encoding="utf-8", delete=False) as tmp:
        tmp.write(source)
        tmp_path = Path(tmp.name)

    # Configure mmdc with high maxTextSize and maxEdges limits to prevent premature truncation
    mermaid_cfg = {
        "maxTextSize": 5000000,
        "maxEdges": 2000,
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as cfg_tmp:
        json.dump(mermaid_cfg, cfg_tmp)
        cfg_path = Path(cfg_tmp.name)

    pup_config = os.environ.get("PUPPETEER_CONFIG") or ("/etc/puppeteer-config.json" if os.path.exists("/etc/puppeteer-config.json") else None)
    user_mermaid_cfg = os.environ.get("MERMAID_CONFIG")
    chosen_cfg = user_mermaid_cfg if (user_mermaid_cfg and os.path.exists(user_mermaid_cfg)) else str(cfg_path)

    try:
        cmd = [mmdc, "-i", str(tmp_path), "-o", str(output_path), "-c", chosen_cfg]
        if pup_config and os.path.exists(pup_config):
            cmd.extend(["-p", pup_config])
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            if "Maximum text size in diagram exceeded" in err or "Edge limit exceeded" in err:
                raise ImageRenderError(
                    f"Mermaid complexity limit exceeded ({err}). "
                    "Use '--diagram-detail architecture' or '--max-diagram-nodes 100' to generate a clean, focused architecture diagram."
                )
            raise ImageRenderError(f"mmdc failed (exit {res.returncode}): {err}")
    finally:
        for p in (tmp_path, cfg_path):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise ImageRenderError(f"mmdc finished without generating {output_path}")

    # Detect Mermaid's internal rendered error box in output files
    if image_format.lower() == "svg":
        try:
            svg_text = output_path.read_text(encoding="utf-8", errors="replace")
            if "Maximum text size in diagram exceeded" in svg_text or "Edge limit exceeded" in svg_text:
                raise ImageRenderError(
                    f"Mermaid diagram text exceeded renderer limit ({len(source)} chars). "
                    "Use '--diagram-detail architecture' or '--max-diagram-nodes 100' to generate a clean, focused architecture view."
                )
        except OSError:
            pass
    elif image_format.lower() == "png":
        # Mermaid's error box is a fixed 168x76 box (~2.6KB)
        if output_path.stat().st_size < 3500 and len(source) > 20000:
            raise ImageRenderError(
                f"Mermaid diagram exceeded complexity limits ({len(source)} chars). "
                "Use '--diagram-detail architecture' or '--max-diagram-nodes 100' to generate a clean, focused architecture view."
            )


def render_kroki(
    source: str,
    output_path: Path,
    image_format: str = "png",
    endpoint: str | None = None,
    timeout: float = 30.0,
) -> None:
    """Render Mermaid source using Kroki HTTP service."""
    fmt = image_format.lower()
    if fmt not in {"png", "svg", "jpeg"}:
        raise ImageRenderError(
            f"Kroki only supports 'png' and 'svg' for Mermaid diagrams, not '{image_format}'."
        )

    base = (
        endpoint
        or os.environ.get("GITDIAGRAM_IMAGE_ENDPOINT")
        or os.environ.get("KROKI_ENDPOINT")
        or "https://kroki.io"
    ).rstrip("/")
    url = f"{base}/mermaid/{fmt}"
    data = source.encode("utf-8")
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "User-Agent": "gitdiagram",
        "Accept": "image/*, application/*, */*",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace").strip()
        raise ImageRenderError(f"Kroki rendering HTTP error {exc.code}: {err_body}") from exc
    except urllib.error.URLError as exc:
        raise ImageRenderError(f"Kroki connection failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ImageRenderError(f"Kroki request timed out after {timeout}s") from exc
    except Exception as exc:
        raise ImageRenderError(f"Failed to fetch image from Kroki: {exc}") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(content)


def render_mermaid_ink(
    source: str,
    output_path: Path,
    image_format: str = "png",
    endpoint: str | None = None,
    timeout: float = 30.0,
) -> None:
    """Render Mermaid source using mermaid.ink HTTP service."""
    fmt = image_format.lower()
    if fmt == "png":
        path_type = "img"
    elif fmt == "svg":
        path_type = "svg"
    else:
        raise ImageRenderError(
            f"mermaid.ink only supports 'png' and 'svg', not '{image_format}'."
        )

    state = {"code": source, "mermaid": {"theme": "default"}}
    raw = json.dumps(state).encode("utf-8")
    compressed = zlib.compress(raw, 9)
    encoded = base64.urlsafe_b64encode(compressed).decode("ascii")

    base = (
        endpoint
        or os.environ.get("GITDIAGRAM_IMAGE_ENDPOINT")
        or "https://mermaid.ink"
    ).rstrip("/")
    url = f"{base}/{path_type}/pako:{encoded}"
    headers = {
        "User-Agent": "gitdiagram",
        "Accept": "image/*, */*",
    }
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace").strip()
        raise ImageRenderError(f"mermaid.ink HTTP error {exc.code}: {err_body}") from exc
    except urllib.error.URLError as exc:
        raise ImageRenderError(f"mermaid.ink connection failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ImageRenderError(f"mermaid.ink request timed out after {timeout}s") from exc
    except Exception as exc:
        raise ImageRenderError(f"Failed to fetch image from mermaid.ink: {exc}") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(content)


def render_image(
    mermaid_source: str,
    output_path: Path,
    image_format: str = "png",
    provider: str = "auto",
    endpoint: str | None = None,
    timeout: float = 30.0,
    offline: bool = False,
) -> Path:
    """Render a Mermaid diagram source to an image file.

    Args:
        mermaid_source: The Mermaid diagram text.
        output_path: Path to write the output image to.
        image_format: 'png', 'svg', or 'pdf' (default: 'png').
        provider: 'auto', 'local', 'kroki', or 'mermaid.ink' (default: 'auto').
        endpoint: Custom HTTP endpoint URL (optional).
        timeout: Request or subprocess timeout in seconds.
        offline: Disallow remote network rendering services.

    Returns:
        The Path to the written image.
    """
    source = sanitize_mermaid(mermaid_source)
    fmt = image_format.lower().lstrip(".")
    if fmt not in {"png", "svg", "pdf"}:
        raise ValueError(
            f"Unsupported image format: {image_format}. Must be one of: png, svg, pdf"
        )

    is_offline = offline or os.environ.get("GITDIAGRAM_OFFLINE", "").strip().lower() in {"1", "true", "yes"}

    env_provider = os.environ.get("GITDIAGRAM_IMAGE_PROVIDER", "").strip().lower()
    chosen_provider = env_provider or provider.lower()

    if is_offline and chosen_provider in {"kroki", "mermaid.ink"}:
        raise ImageRenderError(
            f"Provider '{chosen_provider}' requires an internet connection, which is blocked in offline mode. "
            "Use local provider 'local' (mmdc)."
        )

    if chosen_provider == "local":
        render_local_mmdc(source, output_path, fmt, timeout=timeout)
        return output_path
    elif chosen_provider == "kroki":
        render_kroki(source, output_path, fmt, endpoint=endpoint, timeout=timeout)
        return output_path
    elif chosen_provider == "mermaid.ink":
        render_mermaid_ink(source, output_path, fmt, endpoint=endpoint, timeout=timeout)
        return output_path
    elif chosen_provider == "auto":
        # 1. Prefer local mmdc if installed
        if shutil.which("mmdc"):
            try:
                render_local_mmdc(source, output_path, fmt, timeout=timeout)
                return output_path
            except ImageRenderError:
                if is_offline:
                    raise
                pass

        if is_offline:
            raise ImageRenderError(
                "Offline mode is active and local Mermaid CLI ('mmdc') was not found on PATH. "
                "Install it with 'npm install -g @mermaid-js/mermaid-cli', or disable offline mode."
            )

        if fmt == "pdf":
            raise ImageRenderError(
                "PDF output requires local mermaid-cli ('mmdc'). "
                "Install it globally via 'npm install -g @mermaid-js/mermaid-cli', "
                "or choose 'png' or 'svg'."
            )

        # 2. Try Kroki
        errors: list[str] = []
        try:
            render_kroki(source, output_path, fmt, endpoint=endpoint, timeout=timeout)
            return output_path
        except ImageRenderError as exc:
            errors.append(f"Kroki: {exc}")

        # 3. Fallback to mermaid.ink
        try:
            render_mermaid_ink(source, output_path, fmt, endpoint=endpoint, timeout=timeout)
            return output_path
        except ImageRenderError as exc:
            errors.append(f"mermaid.ink: {exc}")

        combined = "; ".join(errors)
        raise ImageRenderError(
            f"Could not render diagram image ({combined}). "
            "For offline rendering, install mermaid-cli: npm install -g @mermaid-js/mermaid-cli"
        )
    else:
        raise ValueError(f"Unknown image provider: {provider}")


def main(argv: list[str] | None = None) -> int:
    """CLI helper to convert a Mermaid diagram file (.mmd) into an image."""
    parser = argparse.ArgumentParser(
        prog="gitdiagram-render-image",
        description="Convert a Mermaid (.mmd) diagram file into an image (PNG, SVG, PDF).",
    )
    parser.add_argument("input", type=Path, help="path to input .mmd file")
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=None,
        help="path to output image file (default: same name with image extension)",
    )
    parser.add_argument(
        "--format",
        choices=["png", "svg", "pdf"],
        default=None,
        help="output format (default: inferred from output path or png)",
    )
    parser.add_argument(
        "--provider",
        choices=["auto", "local", "kroki", "mermaid.ink"],
        default="auto",
        help="rendering provider: auto, local (mmdc), kroki, mermaid.ink (default: auto)",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="custom HTTP endpoint for diagram rendering service",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="timeout in seconds (default: 30)",
    )

    args = parser.parse_args(argv)
    if not args.input.exists():
        print(f"error: input file does not exist: {args.input}", file=sys.stderr)
        return 1

    fmt = args.format
    if fmt is None:
        if args.output and args.output.suffix:
            ext = args.output.suffix.lstrip(".").lower()
            if ext in {"png", "svg", "pdf"}:
                fmt = ext
        if fmt is None:
            fmt = "png"

    out_path = args.output
    if out_path is None:
        out_path = args.input.with_suffix(f".{fmt}")

    try:
        source = args.input.read_text(encoding="utf-8")
        render_image(
            mermaid_source=source,
            output_path=out_path,
            image_format=fmt,
            provider=args.provider,
            endpoint=args.endpoint,
            timeout=args.timeout,
        )
        print(f"wrote {out_path}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
