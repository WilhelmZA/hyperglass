"""Execute validated & constructed query on device.

Accepts input from front end application, validates the input and
returns errors if input is invalid. Passes validated parameters to
construct.py, which is used to build & run the Netmiko connections or
http client API calls, returns the output back to the front end.
"""

# Standard Library
import time
import signal
from typing import TYPE_CHECKING, Any, Dict, Union, Callable

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.util.typing import is_series
from hyperglass.util.query_samples import log_query_sample
from hyperglass.exceptions.public import DeviceTimeout, ResponseEmpty

if TYPE_CHECKING:
    from hyperglass.models.api import Query
    from .drivers import Connection
    from hyperglass.models.data import OutputDataModel

# Local
from .drivers import HttpClient, NetmikoConnection


def map_driver(driver_name: str) -> "Connection":
    """Get the correct driver class based on the driver name."""

    if driver_name == "hyperglass_http_client":
        return HttpClient

    return NetmikoConnection


def handle_timeout(**exc_args: Any) -> Callable:
    """Return a function signal can use to raise a timeout exception."""

    def handler(*args: Any, **kwargs: Any) -> None:
        raise DeviceTimeout(**exc_args)

    return handler


async def execute(query: "Query") -> Union["OutputDataModel", str]:
    """Initiate query validation and execution."""
    params = use_state("params")
    output = params.messages.general
    _log = log.bind(query=query.summary(), device=query.device.id)
    _log.debug("")

    mapped_driver = map_driver(query.device.driver)
    driver: "Connection" = mapped_driver(query.device, query)

    signal.signal(
        signal.SIGALRM,
        handle_timeout(error=TimeoutError("Connection timed out"), device=query.device),
    )
    signal.alarm(params.request_timeout - 1)

    # Capture the raw device output and parsed result (and failures) as JSONL
    # samples when logging.samples is enabled. Best-effort; never affects the query.
    samples = params.logging.samples
    started = time.monotonic()
    response = None
    output = None

    try:
        if query.device.proxy:
            proxy = driver.setup_proxy()
            with proxy() as tunnel:
                response = await driver.collect(tunnel.local_bind_host, tunnel.local_bind_port)
        else:
            response = await driver.collect()

        output = await driver.response(response)

        if is_series(output):
            if len(output) == 0:
                raise ResponseEmpty(query=query)
            output = "\n\n".join(output)

        elif isinstance(output, str):
            # If the output is a string (not structured) and is empty,
            # produce an error.
            if output == "" or output == "\n":
                raise ResponseEmpty(query=query)

        elif isinstance(output, Dict):
            # If the output an empty dict, responses have data, produce an
            # error.
            if not output:
                raise ResponseEmpty(query=query)

    except Exception as error:
        if samples.enable:
            log_query_sample(
                query,
                samples,
                params.logging.directory,
                raw=response,
                parsed=output,
                error=error,
                runtime=round(time.monotonic() - started, 4),
                structured=output is not None and not isinstance(output, str),
            )
        raise
    finally:
        signal.alarm(0)

    if samples.enable:
        log_query_sample(
            query,
            samples,
            params.logging.directory,
            raw=response,
            parsed=output,
            error=None,
            runtime=round(time.monotonic() - started, 4),
            structured=output is not None and not isinstance(output, str),
        )

    return output
