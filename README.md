![Ultraglass logo](hyperglass/images/ultraglass-light.svg)

Ultraglass is a network looking glass for operators who want to publish useful visibility into their network without giving users direct access to network devices.

Operators can expose BGP route, BGP community, BGP AS path, ping, and traceroute queries through a web interface and REST API. Queries run from configured network devices, and the administrator controls the commands, targets, credentials, text, theme, and access rules.

Ultraglass is a maintained fork of [hyperglass](https://github.com/thatmattlove/hyperglass). The application keeps the `hyperglass` Python package and command names for compatibility with existing deployments, while the public product, repository, documentation, and container image use the Ultraglass name.

## What it does

- Runs network diagnostics from selected routers or locations.
- Supports BGP route, BGP community, BGP AS path, ping, and traceroute queries.
- Provides structured BGP and traceroute output where the device platform supports it.
- Enriches routes and traceroute hops with ASN, organisation, country, IXP, and reverse DNS data when enabled.
- Supports IPv4 and IPv6, VRFs, SSH proxy servers, HTTP devices, and concurrent queries.
- Applies prefix-list and access-list style controls to query targets.
- Provides a responsive web UI and configurable OpenAPI documentation.
- Lets administrators customise the theme, logo, menus, labels, messages, directives, and error handling.

## Supported platforms

Ultraglass includes built-in support for Arista EOS, BIRD, Cisco IOS, Cisco NX-OS, Cisco IOS-XR, FRRouting, Huawei VRP, Juniper Junos, MikroTik, Nokia SR OS, OpenBGPD, TNSR, and VyOS. Netmiko provides the underlying device connectivity, so other supported platforms can be configured when their commands and output match the required query types.

Structured BGP route output is available for Arista EOS, FRRouting, Huawei VRP, Juniper Junos, and MikroTik RouterOS. Structured traceroute output is available for FRRouting, Huawei VRP, and MikroTik RouterOS or SwitchOS.

## Quick start

The repository includes a sample configuration and a fake device so you can verify the application before connecting it to production routers.

### Docker

```shell
git clone https://github.com/WilhelmZA/ultraglass.git --depth=1
cd ultraglass
mkdir -p /etc/hyperglass
cp .samples/sample_devices.yaml /etc/hyperglass/devices.yaml
docker compose up
```

Open `http://localhost:8001` after the containers start. The sample device returns fake output and does not connect to a network device.

### Manual installation

Manual installation requires Python 3.13 or later, Node.js 22 or later, pnpm 11, and Redis 7. Install the project into a virtual environment, create `/etc/hyperglass`, copy the sample device file, and start the application with `hyperglass start`. The full procedure is in the [manual installation guide](docs/content/installation/manual.mdx).

## Documentation

- [Ultraglass Wiki](https://github.com/WilhelmZA/ultraglass/wiki)
- [Documentation home](docs/content/index.mdx)
- [Installation](docs/content/installation.mdx)
- [User guide](docs/content/user-guide.mdx)
- [Configuration](docs/content/configuration/overview.mdx)
- [Supported platforms](docs/content/platforms.mdx)
- [Plugins](docs/content/plugins.mdx)
- [Changelog](CHANGELOG.md)
- [Clear BSD license](LICENSE)

## Reporting bugs

Use the [bug report form](https://github.com/WilhelmZA/ultraglass/issues/new/choose) and include the Ultraglass version, deployment method, steps to reproduce, expected behaviour, observed behaviour, relevant configuration with secrets removed, and a local `hyperglass support-bundle` output. The bundle is never submitted automatically. Review it before attaching it and do not include device passwords, private keys, tokens, or unredacted internal addresses.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Changes should keep the backend and UI checks passing, preserve IPv4 and IPv6 support, and avoid hard-coding text or deployment-specific values that administrators should be able to configure.

## Acknowledgements

Ultraglass is distributed under the [Clear BSD License](LICENSE) and retains the required upstream attribution. It is built with [Netmiko](https://github.com/ktbyers/netmiko), [Litestar](https://litestar.dev), [Pydantic](https://docs.pydantic.dev/latest/), [React](https://react.dev/), [Next.js](https://nextjs.org/), [Chakra UI](https://chakra-ui.com/), [React Flow](https://reactflow.dev/), and [BGP.tools](https://bgp.tools/).
