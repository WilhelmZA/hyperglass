"""Structured data configuration variables."""

# Standard Library
import typing as t

# Third Party
from pydantic import model_validator

# Local
from ..main import HyperglassModel

StructuredCommunityMode = t.Literal["permit", "deny"]
StructuredRPKIMode = t.Literal["router", "external"]
StructuredRPKIBackend = t.Literal["cloudflare", "routinator"]


class StructuredCommunities(HyperglassModel):
    """Control structured data response for BGP communities."""

    mode: StructuredCommunityMode = "deny"
    items: t.List[str] = []


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
