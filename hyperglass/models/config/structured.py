"""Structured data configuration variables."""

# Standard Library
import typing as t

# Third Party
from pydantic import ValidationInfo, field_validator, model_validator

# Local
from ..main import HyperglassModel

StructuredCommunityMode = t.Literal["permit", "deny", "name"]
StructuredRPKIMode = t.Literal["router", "external"]
StructuredRPKIBackend = t.Literal["cloudflare", "routinator"]


class StructuredCommunities(HyperglassModel):
    """Control structured data response for BGP communities."""

    mode: StructuredCommunityMode = "deny"
    items: t.List[str] = []
    names: t.Dict[str, str] = {}

    @field_validator("names")
    def validate_names(cls, value: t.Dict[str, str], info: ValidationInfo) -> t.Dict[str, str]:
        """Require at least one community mapping when mode is 'name'."""
        if info.data and info.data.get("mode") == "name" and not value:
            raise ValueError(
                "When using mode 'name', at least one community mapping must be "
                "provided in 'names'"
            )
        return value


class StructuredRpki(HyperglassModel):
    """Control structured data response for RPKI state."""

    mode: StructuredRPKIMode = "router"
    backend: StructuredRPKIBackend = "cloudflare"
    rpki_server_url: str = ""

    @model_validator(mode="after")
    def validate_routinator_url(self) -> "StructuredRpki":
        """Require a server URL when the routinator backend is selected."""
        if self.backend == "routinator" and not self.rpki_server_url:
            raise ValueError(
                "structured.rpki.rpki_server_url is required when backend is 'routinator'"
            )
        return self


class Structured(HyperglassModel):
    """Control structured data responses."""

    communities: StructuredCommunities = StructuredCommunities()
    rpki: StructuredRpki = StructuredRpki()

    # Top-level structured enable/disable flags. If `structured:` is present in
    # the user's config and these are not set (None), the structured table
    # output is considered enabled by default. Setting them to False disables
    # the structured table output even when a `structured:` block exists.
    enable_for_traceroute: t.Optional[bool] = None
    enable_for_bgp_route: t.Optional[bool] = None
