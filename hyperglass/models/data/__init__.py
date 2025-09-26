"""Data structure models."""

# Standard Library
from typing import Union

# Local
from .bgp_route import BGPRouteTable
from .traceroute import TracerouteResult

OutputDataModel = Union[BGPRouteTable, TracerouteResult]

__all__ = (
    "BGPRouteTable",
    "TracerouteResult", 
    "OutputDataModel",
)
