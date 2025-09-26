"""Structured data configuration variables."""

# Standard Library
import typing as t

# Third Party
from pydantic import field_validator, ValidationInfo

# Local
from ..main import HyperglassModel

StructuredCommunityMode = t.Literal["permit", "deny", "name"]
StructuredRPKIMode = t.Literal["router", "external"]


class StructuredCommunities(HyperglassModel):
    """Control structured data response for BGP communities."""

    mode: StructuredCommunityMode = "deny"
    items: t.List[str] = []
    names: t.Dict[str, str] = {}

    @field_validator("names")
    def validate_names(cls, value: t.Dict[str, str], info: ValidationInfo) -> t.Dict[str, str]:
        """Validate that names are provided when mode is 'name'."""
        if info.data and info.data.get("mode") == "name" and not value:
            raise ValueError(
                "When using mode 'name', at least one community mapping must be provided in 'names'"
            )
        return value


class StructuredRpki(HyperglassModel):
    """Control structured data response for RPKI state."""

    mode: StructuredRPKIMode = "router"
    backend: str = "cloudflare"
    rpki_server_url: str = ""


class StructuredBgpTools(HyperglassModel):
    """Control BGP.tools enrichment for structured data responses."""

    enabled: bool = True
    cache_timeout: int = 86400  # 24 hours in seconds
    enrich_next_hop: bool = True
    enrich_traceroute: bool = True


class Structured(HyperglassModel):
    """Control structured data responses."""

    communities: StructuredCommunities = StructuredCommunities()
    rpki: StructuredRpki = StructuredRpki()
    bgp_tools: StructuredBgpTools = StructuredBgpTools()
