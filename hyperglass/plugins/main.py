"""Register all plugins."""

# Standard Library
import sys
import shutil
import typing as t
from inspect import isclass, getmembers
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

# Local
from . import _builtin
from ._input import InputPlugin
from ._output import OutputPlugin
from ._manager import InputPluginManager, OutputPluginManager


def _is_class(module: t.Any, obj: object) -> bool:
    if isclass(obj):
        # Get the object's containing module name.
        obj_module_name: str = getattr(obj, "__module__", "")
        # Get the module's name.
        module_name: str = getattr(module, "__name__", None)
        # Only validate objects that are members of the module.
        return module_name in obj_module_name
    return False


def _register_from_module(module: t.Any, **kwargs: t.Any) -> t.Tuple[str, ...]:
    """Register defined classes from the module."""
    failures = ()
    defs = getmembers(module, lambda o: _is_class(module, o))
    sys.modules[module.__name__] = module
    for name, plugin in defs:
        if issubclass(plugin, OutputPlugin):
            manager = OutputPluginManager()
        elif issubclass(plugin, InputPlugin):
            manager = InputPluginManager()
        else:
            failures += (name,)
            continue
        manager.register(plugin, **kwargs)
    return failures


def _module_from_file(file: Path) -> t.Any:
    """Import a plugin module from its file Path object."""
    plugins_dir = Path(__file__).parent / "external"
    dst = plugins_dir / f"imported_{file.name}"
    shutil.copy2(file, dst)
    name = f"imported_{file.name.split('.')[0]}"
    spec = spec_from_file_location(f"hyperglass.plugins.external.{name}", dst)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def init_builtin_plugins() -> None:
    """Initialize all built-in plugins."""
    _register_from_module(_builtin)


def register_plugin(plugin_file: Path, **kwargs) -> t.Tuple[str, ...]:
    """Register an external plugin by file path."""
    if plugin_file.exists():
        module = _module_from_file(plugin_file)
        results = _register_from_module(module, ref=plugin_file.stem, **kwargs)
        return results
    raise FileNotFoundError(str(plugin_file))


def register_all_plugins() -> None:
    """Validate and register all built-in and configured plugins.

    The registry lives in Redis alongside the rest of the state, so it is lost with
    everything else if the store is emptied. Registering is idempotent, which is what
    lets state recovery call this as well as startup.
    """
    # Project
    from hyperglass.log import log
    from hyperglass.state import use_state

    state = use_state()

    # Register built-in plugins.
    init_builtin_plugins()

    failures = ()

    # Register external directive-based plugins (defined in directives).
    for plugin_file, directives in state.devices.directive_plugins().items():
        failures += register_plugin(plugin_file, directives=directives)

    # Register external global/common plugins (defined in config).
    for plugin_file in state.params.common_plugins():
        failures += register_plugin(plugin_file, common=True)

    for failure in failures:
        log.bind(plugin=failure).warning("Invalid hyperglass plugin")
