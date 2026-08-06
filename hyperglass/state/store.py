"""Primary state container."""

# Standard Library
import typing as t

# Project
from hyperglass.exceptions.private import StateError

# Local
from .manager import StateManager
from .recovery import rebuild_state

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.ui import UIParameters
    from hyperglass.plugins._base import HyperglassPlugin
    from hyperglass.models.directive import Directive, Directives
    from hyperglass.models.config.params import Params
    from hyperglass.models.config.devices import Devices

    # Local
    from .manager import RedisManager


PluginT = t.TypeVar("PluginT", bound="HyperglassPlugin")


class HyperglassState(StateManager):
    """Primary hyperglass state container."""

    def add_plugin(self, _type: str, plugin: "HyperglassPlugin") -> None:
        """Add a plugin to its list by type."""
        current = self.plugins(_type)
        self.redis.set(("plugins", _type), list({*current, plugin}))

    def remove_plugin(self, _type: str, plugin: "HyperglassPlugin") -> None:
        """Remove a plugin from its list by type."""
        current = self.plugins(_type)
        plugins = {p for p in current if p != plugin}
        self.redis.set(("plugins", _type), list(plugins))

    def reset_plugins(self, _type: str) -> None:
        """Remove all plugins of `_type`."""
        self.redis.set(("plugins", _type), [])

    def add_directive(self, *directives: t.Union["Directive", t.Dict[str, t.Any]]) -> None:
        """Add a directive."""
        current = self.directives
        current.add(*directives, unique_by="id")
        self.redis.set("directives", current)

    def clear(self) -> None:
        """Delete all hyperglass cache keys.

        Scoped to the state namespace rather than flushing the database, so hyperglass
        does not delete keys belonging to anything else sharing the Redis database.
        Note that two hyperglass instances sharing a database still share this
        namespace and will clear each other on start; give each its own
        `HYPERGLASS_REDIS_DB`.
        """
        batch = []
        for key in self.redis.instance.scan_iter(match=f"{self.redis.namespace}.*", count=500):
            batch.append(key)
            if len(batch) == 500:
                self.redis.instance.delete(*batch)
                batch = []
        if batch:
            self.redis.instance.delete(*batch)

    def _required(self, key: str) -> t.Any:
        """Read a value that must exist, rebuilding state if it has been lost.

        Redis is cache-only, so a flush or a replaced Redis container empties the store
        while hyperglass is running and leaves every one of these reads failing until
        the process is restarted. Rebuild and read again instead.

        This sits on the property rather than on `use_state`, because the properties are
        read directly off a state instance on the hot paths (`Query.device` and the query
        route both do it), and those reads never pass through `use_state`.
        """
        try:
            return self.redis.get(key, raise_if_none=True)
        except StateError:
            if not rebuild_state(self.redis):
                raise
            return self.redis.get(key, raise_if_none=True)

    @property
    def cache(self) -> "RedisManager":
        """Get the redis manager instance."""
        return self.redis

    @property
    def params(self) -> "Params":
        """Get hyperglass configuration parameters (`hyperglass.yaml`)."""
        return self._required("params")

    @property
    def devices(self) -> "Devices":
        """Get hyperglass devices (`devices.yaml`)."""
        return self._required("devices")

    @property
    def ui_params(self) -> "UIParameters":
        """UI parameters, built from params."""
        return self._required("ui_params")

    @property
    def directives(self) -> "Directives":
        """All directives."""
        return self._required("directives")

    @property
    def generation(self) -> t.Optional[str]:
        """Identifier for the current population of state.

        Written every time configuration is loaded into Redis, so a consumer can tell a
        rebuilt store from the one it started with. `None` means state has been lost.
        """
        return self.redis.get("generation", raise_if_none=False)

    def plugins(self, _type: str) -> t.List[PluginT]:
        """Get plugins by type."""
        return self.redis.get(("plugins", _type), raise_if_none=False, value_if_none=[])
