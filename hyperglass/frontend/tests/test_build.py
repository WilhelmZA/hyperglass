"""Tests for the packaged UI build workspace."""

# Standard Library
from pathlib import Path

# Third Party
import pytest

# Project
from hyperglass.frontend import _prepare_ui_build_dir, generate_favicons


def test_prepare_ui_build_dir_is_writable_and_excludes_generated_files(tmp_path: Path) -> None:
    """Copy UI source into an application-local build directory without caches."""
    ui_dir = _prepare_ui_build_dir(tmp_path)

    assert ui_dir == tmp_path / ".ui"
    assert (ui_dir / "package.json").exists()
    assert not (ui_dir / "node_modules").exists()
    assert not (ui_dir / ".next").exists()
    assert not (ui_dir / "out").exists()
    assert not (ui_dir / "hyperglass.json").exists()


def test_generate_favicons_from_svg(tmp_path: Path) -> None:
    """Generate the complete favicon set from the built-in SVG icon."""
    pytest.importorskip("cairosvg")
    source = Path(__file__).parents[2] / "images" / "ultraglass-icon.svg"
    output = tmp_path / "favicons"

    formats = generate_favicons(source, output)

    assert len(formats) == 21
    assert (output / "favicon-64x64.ico").exists()
    assert (output / "favicon-196x196.png").exists()
