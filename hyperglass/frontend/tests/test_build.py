"""Tests for the packaged UI build workspace."""

# Standard Library
import asyncio
from pathlib import Path

# Third Party
import pytest

# Project
from hyperglass.frontend import (
    PACKAGE_PNPM_STORE,
    _prepare_ui_build_dir,
    _read_ui_export_version,
    _ui_export_matches_version,
    _ui_subprocess_env,
    build_frontend,
    generate_favicons,
)


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
    assert (ui_dir / ".npmrc").read_text() == f"store-dir={PACKAGE_PNPM_STORE}\n"


def test_ui_subprocess_env_pins_pnpm_store() -> None:
    """UI subprocesses must use the packaged pnpm store, not app_path."""
    env = _ui_subprocess_env()
    assert env["PNPM_CONFIG_STORE_DIR"] == str(PACKAGE_PNPM_STORE)


def test_read_ui_export_version_from_index_html(tmp_path: Path) -> None:
    """Read the exported UI version from the hyperglass-version meta tag."""
    ui_dir = tmp_path / "static" / "ui"
    ui_dir.mkdir(parents=True)
    (ui_dir / "index.html").write_text(
        '<meta name="hyperglass-version" content="3.1.0" />',
        encoding="utf-8",
    )

    assert _read_ui_export_version(tmp_path) == "3.1.0"


def test_ui_export_matches_version_rejects_stale_export(tmp_path: Path) -> None:
    """A persisted export from an older release must not suppress rebuilds."""
    ui_dir = tmp_path / "static" / "ui"
    ui_dir.mkdir(parents=True)
    (ui_dir / "index.html").write_text(
        '<meta name="hyperglass-version" content="3.1.0" />',
        encoding="utf-8",
    )

    assert _ui_export_matches_version(tmp_path, "3.2.0") is False
    assert _ui_export_matches_version(tmp_path, "3.1.0") is True


@pytest.mark.parametrize("index_html", (None, "<html></html>"))
def test_ui_export_matches_version_rejects_incomplete_export(
    tmp_path: Path, index_html: str | None
) -> None:
    """An incomplete export must not suppress a required rebuild."""
    ui_dir = tmp_path / "static" / "ui"
    ui_dir.mkdir(parents=True)
    if index_html is not None:
        (ui_dir / "index.html").write_text(index_html, encoding="utf-8")

    assert _ui_export_matches_version(tmp_path, "3.2.0") is False


def test_generate_favicons_from_svg(tmp_path: Path) -> None:
    """Generate the complete favicon set from the built-in SVG icon."""
    pytest.importorskip("cairosvg")
    source = Path(__file__).parents[2] / "images" / "ultraglass-icon.svg"
    output = tmp_path / "favicons"

    formats = generate_favicons(source, output)

    assert len(formats) == 21
    assert (output / "favicon-64x64.ico").exists()
    assert (output / "favicon-196x196.png").exists()


def test_failed_build_does_not_record_build_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed build must not make a stale export appear current."""
    package_ui = tmp_path / "package-ui"
    package_ui.mkdir()
    (package_ui / "package.json").write_text("{}")
    (package_ui / "node_modules").mkdir()
    monkeypatch.setattr("hyperglass.frontend.PACKAGE_UI_DIR", package_ui)

    app_path = tmp_path / "app"
    (app_path / "static" / "ui").mkdir(parents=True)
    (app_path / "static" / "images" / "favicons").mkdir(parents=True)
    dot_env_file = app_path / ".ui" / ".env"
    dot_env_file.parent.mkdir()
    dot_env_file.write_text("HYPERGLASS_BUILD_ID=old-build")

    class Logo:
        favicon = package_ui / "favicon.svg"

    class Web:
        logo = Logo()
        opengraph = type("OpenGraph", (), {"image": package_ui / "opengraph.png"})()
        theme = type("Theme", (), {"colors": type("Colors", (), {"black": "#000000"})()})()

    class Params:
        web = Web()

        def export_json(self, by_alias: bool) -> str:
            return "{}"

        def export_dict(self) -> dict:
            return {}

    async def fail_build(*args, **kwargs):
        raise RuntimeError("build failed")

    async def skip_node_initial(*args, **kwargs):
        return ""

    monkeypatch.setattr("hyperglass.frontend.build_ui", fail_build)
    monkeypatch.setattr("hyperglass.frontend.node_initial", skip_node_initial)
    monkeypatch.setattr("hyperglass.frontend.generate_favicons", lambda *args: ())

    with pytest.raises(RuntimeError, match="build failed"):
        asyncio.run(
            build_frontend(
                dev_mode=False,
                dev_url="http://localhost/",
                prod_url="/api/",
                params=Params(),
                app_path=app_path,
            )
        )

    assert "HYPERGLASS_BUILD_ID" not in dot_env_file.read_text()
