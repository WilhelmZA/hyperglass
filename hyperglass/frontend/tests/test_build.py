"""Tests for the packaged UI build workspace."""

# Standard Library
from pathlib import Path

# Third Party
import pytest

# Project
from hyperglass.frontend import _prepare_ui_build_dir, generate_favicons


def test_prepare_ui_build_dir_reuses_packaged_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reuse dependencies bundled in the container rather than copying them."""
    package_ui = tmp_path / "package-ui"
    package_ui.mkdir()
    (package_ui / "package.json").write_text("{}")
    (package_ui / "node_modules").mkdir()
    (package_ui / "node_modules" / "dependency").mkdir()
    monkeypatch.setattr("hyperglass.frontend.PACKAGE_UI_DIR", package_ui)

    ui_dir = _prepare_ui_build_dir(tmp_path / "app")

    assert ui_dir == tmp_path / "app" / ".ui"
    assert (ui_dir / "package.json").exists()
    assert (ui_dir / "node_modules").is_symlink()
    assert (ui_dir / "node_modules").resolve() == package_ui / "node_modules"
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
