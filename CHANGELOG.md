# Changelog

This is the changelog for [WilhelmZA/ultraglass](https://github.com/WilhelmZA/ultraglass), a **fork** of [thatmattlove/hyperglass](https://github.com/thatmattlove/hyperglass). It documents Ultraglass changes, not upstream's.

The fork's own version line starts at **3.0.0** and is currently at **3.1.0**. It is based on **upstream hyperglass 2.0.4**, plus the upstream commits that had landed on upstream `main` after 2.0.4 but were never released by upstream. Upstream's version numbering is unrelated to this one; upstream's own history continues at [thatmattlove/hyperglass/blob/main/CHANGELOG.md](https://github.com/thatmattlove/hyperglass/blob/main/CHANGELOG.md).

Everything from [2.0.4](#204---2024-06-30) downward is inherited upstream history, kept verbatim for reference.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 3.1.0 - 2026-08-25

Security and platform hardening release covering the dependency estate, container build, documentation platform and frontend validation.

### Added

- Nextra 4 documentation application using Next.js 15, React 19, the App Router and the migrated `docs/content` route tree, exporting all 33 documentation routes.
- A compatibility patch for `nextra-theme-docs@4.6.1` so the Nextra layout schema accepts the React 19 layout configuration.
- Deterministic DNS-over-HTTPS UI tests that validate provider URLs, query types, headers and parsed IPv4 and IPv6 answers without depending on external network availability.

### Changed

- The Python package, runtime metadata, UI package, upgrade guide and issue templates now identify the release as `3.1.0`.
- The version helper now targets the migrated `docs/content/installation/upgrading.mdx` path.
- Structured-output TypeScript models now include optional BGP next-hop enrichment fields and correctly distinguish BGP and traceroute responses.
- UI table components now use generic column and cell types instead of permissive `any` fallbacks.
- The frontend timeout helper now uses the caller-provided `AbortController` signal.
- The Docker build installs the pinned dependency closure with the patched npm and pnpm toolchain, then removes build-only package tooling from the final image.

### Security

- Raised vulnerable dependency floors and lockfile overrides for the fixable HIGH CVEs identified by the container scan, including Brotli, cryptography, lxml, multipart, Pillow and psutil.
- Updated frontend dependency overrides for the affected `ua-parser-js`, `@babel/runtime` and `@babel/helpers` packages.
- Final Trivy validation reports zero HIGH or CRITICAL vulnerabilities in the Alpine OS, Python packages, UI packages and docs package.

### Fixed

- Resolved strict UI type errors in route enrichment, structured-output narrowing, traceroute rendering and generic table usage.
- Cleared all UI Biome lint and formatting diagnostics.
- Removed live DNS test flakiness caused by external provider availability and cross-realm `AbortSignal` objects in jsdom.

### Validation

- Python test suite: 70 passed.
- UI test suite: 39 passed.
- UI TypeScript, lint and formatting checks: passed.
- Documentation typecheck and production export: passed for 33 routes.
- Docker image build: passed.
- `/mnt/AppData` compose validation: application reached HTTP 200 after its runtime UI build.

## 3.0.0 - 2026-08-06

First release of the fork. The major version bump reflects a raised Python floor (3.13), the removal of the `hyperglass.external.bgptools` module, and changed default directive commands for FRRouting, Huawei and MikroTik.

### Added

- Structured BGP route output for **MikroTik RouterOS 7+** (`mikrotik_routeros`, `mikrotik_switchos`). New parser `hyperglass/models/parsing/mikrotik.py` (`MikrotikBGPTable`, `MikrotikRouteEntry`, `MikrotikPaths`), output plugin `bgp_routestr_mikrotik`, and three table directives `__hyperglass_mikrotik_bgp_route_table__`, `__hyperglass_mikrotik_bgp_aspath_table__` and `__hyperglass_mikrotik_bgp_community_table__`. Parses `routing route print detail`, including RPKI state, large and extended communities, and active/filtered status.
- Structured BGP route output for **Huawei VRP**. New parser `hyperglass/models/parsing/huawei.py` (`HuaweiBGPTable`, `HuaweiRouteEntry`, `HuaweiPaths`), output plugin `bgp_routestr_huawei`, and the table directives `__hyperglass_huawei_bgp_route_table__`, `__hyperglass_huawei_bgp_aspath_table__` and `__hyperglass_huawei_bgp_community_table__`.
- `SUPPORTED_STRUCTURED_OUTPUT` extended with `huawei`, `mikrotik_routeros` and `mikrotik_switchos`, so `structured_output: true` is now valid on those platforms.
- **Structured traceroute output** for FRRouting, Huawei VRP and MikroTik. New data models `TracerouteResult` and `TracerouteHop` (`hyperglass/models/data/traceroute.py`), a shared parser base in `hyperglass/models/parsing/traceroute.py`, and the output plugins `TraceroutePluginFrr`, `TraceroutePluginHuawei` and `TraceroutePluginMikrotik`. `OutputDataModel` is now `Union[BGPRouteTable, TracerouteResult]`.
- New UI components for structured traceroute: `TracerouteTable`, `TracerouteCell` and the field renderers `MonoField`, `ASNField`, `HostnameField`, `LatencyField` and `LossField` (Hop / IP Address / Hostname / ASN / Loss / Sent / Last / AVG / Best / Worst). Latency is colour-graded and packet loss renders as a badge. `results/individual.tsx` picks the BGP or traceroute table via the new `isBGPStructuredOutput` / `isTracerouteStructuredOutput` type guards.
- New config keys `structured.enable_for_traceroute` and `structured.enable_for_bgp_route` (both `Optional[bool]`, unset means enabled when a `structured` block exists). `Query.device` now returns a per-request device proxy that applies these without mutating global device state.
- **IP and ASN enrichment.** New config block `structured.ip_enrichment` with `enrich_traceroute` and `enrich_bgproute` (both default `false`). Two builtin output plugins, `bgp_route_enrichment` and `traceroute_ip_enrichment`, add ASN, organisation, country, IXP identity and reverse DNS to results. Enrichment failures are swallowed so they cannot fail a query.
- BGP next-hop enrichment: new API fields `BGPRoute.next_hop_asn`, `BGPRoute.next_hop_org` and `BGPRoute.next_hop_country`, plus `BGPRouteTable.asn_organizations` and the async helpers `BGPRouteTable.enrich_with_ip_enrichment()` and `BGPRouteTable.enrich_as_path_organizations()`. The UI renders a `NextHop` field showing ASN, organisation and country on hover.
- AS-path enrichment endpoint `POST /api/aspath/enrich`, which takes `{"as_path": [...]}` (numeric ASNs only, capped at 64) and returns `{"success": true, "asn_organizations": {...}}`. Errors return generic strings rather than internal detail. The AS-path modal calls it lazily when a response has no enrichment data attached.
- AS-path tooltips: every ASN in an AS path renders as a tooltipped link to `https://bgp.tools/as/<asn>` labelled with the organisation name. The AS-path flow chart builds its graph from either BGP AS paths or traceroute hop ASNs, collapsing repeated ASNs and labelling IXP hops by IXP name.
- **Pluggable external RPKI backends.** New config keys `structured.rpki.backend` (`cloudflare` or `routinator`) and `structured.rpki.rpki_server_url`. A validator requires the URL when the backend is `routinator`. Routinator is queried at `<url>/validity`; RPKI state names are normalised so `NotFound`, `not-found` and `unknown` all map correctly.
- **Friendly BGP community names.** New `structured.communities.mode: name` and a `structured.communities.names` map of community to label. In `name` mode no communities are filtered and matched communities render as `<community> - <name>`.
- **Filtered BGP routes are now shown rather than dropped.** New API field `BGPRoute.filtered` and new theme colour `web.theme.colors.filtered` (default `#c1c7cc`). Filtered rows are dimmed in the results table via a new `dimText` prop on `TableRow` and `TableCell`.
- **Opt-in query-sample logging.** New config block `logging.samples` with `enable` (default `false`), `path`, `include_raw`, `include_parsed` and `max_size` (default 50MB). Writes one JSON object per line to `hyperglass_query_log.jsonl` under the logging directory, capturing device, query, runtime, error and optionally raw and parsed output, on both the success and failure paths. Appends are `O_APPEND` so multiple workers are safe, and the file is size-rotated with a single `.1` backup. Raw output can contain internal addressing, so this is off by default.
- New documentation pages: `user-guide.mdx` (end-user guide to locations, query types and FQDN resolution), `configuration/examples/quick-start.mdx` (eight named recipe configurations) and `configuration/config/complete-config.mdx` (key-by-key reference for every configuration option). `structured-output.mdx` expanded to cover every new `structured.*` key with worked examples, and the README rewritten to describe the fork's capabilities.
- Tests for the new parsers and utilities: `test_bgp_route_huawei.py`, `test_bgp_route_mikrotik.py`, `test_traceroute_frr.py`, `test_traceroute_huawei.py`, `test_traceroute_mikrotik.py`, `test_query_samples.py` and `test_system_workers.py`.

### Changed

- **Breaking:** `hyperglass.external.bgptools` is removed and replaced by `hyperglass.external.ip_enrichment`. The new module does real-time bulk WHOIS against `bgp.tools:43` off the event loop, with in-process caching, private and reserved address short-circuiting, and IXP detection. `network_info()` and `network_info_sync()` are kept as compatible shims; `lookup_ip()`, `lookup_asn_name()`, `lookup_asn_country()` and `lookup_asns_bulk()` are new. Anything importing `hyperglass.external.bgptools` directly must be updated.
- **Breaking:** minimum Python raised from 3.11 to 3.13, and the Docker base image moved from `python:3.12.3-alpine` to `python:3.13-alpine`.
- Dependencies modernised: httpx 0.28.1, netmiko 4.6.0, paramiko 4.0.0, pydantic 2.11.9+, pydantic-settings 2.11.0, litestar 2.22.0+, redis 6.4.0, uvicorn 0.37.0, psutil 7.1.0, Pillow 12.2.0+, xmltodict 1.0.2, distro 1.9.0. `poetry.lock` is dropped in favour of the uv lockfiles `requirements.lock` and `requirements-dev.lock`, and the Docker build installs from the lockfile with `--no-deps`.
- Frontend upgraded to Next.js 15. The UI build no longer uses `next export` or `NODE_OPTIONS=--openssl-legacy-provider`; it runs `next build` and copies `out/` into `hyperglass/static/ui`. pnpm workspace configuration migrated to pnpm 11 `allowBuilds`.
- **Default directive commands changed.** MikroTik BGP route queries now use `routing route print detail without-paging where {target} in dst-address bgp and dst-address !=0.0.0.0/0` (RouterOS 7 syntax) instead of `ip route print`; MikroTik traceroute uses `duration=30 count=3` instead of `duration=5 count=1` so loss and RTT statistics are produced; FRRouting traceroute adds `-I -n`; Huawei traceroute uses `tracert -w 500 -q 1 -f 1 -a {source} {target}` with a proper `tracert ipv6` variant.
- netmiko sessions now run in a thread executor instead of inline in the coroutine, so a slow device no longer blocks every other concurrent query. Per-query reads switched from `send_command` to `send_command_timing`, because RouterOS prompt detection truncates output.
- `MikrotikGarbageOutput` is no longer a `common` plugin applied to every device, its hard-coded directive list is gone, and it gained traceroute-aware cleaning that splits repeated RouterOS tables, strips paging prompts and command echoes, and aggregates per-hop rows by highest sent count.
- New input plugin `mikrotik_normalize_input` rewrites a MikroTik BGP route target to its containing /24 or /48, so queries within one subnet share a cache entry.
- The browser no longer calls CAIDA's `api.asrank.caida.org` for ASN organisation names; `useASNDetail` is stubbed and deprecated, and organisation names come from server-side enrichment instead. This removes the last third-party request made from the client.
- Results table page size raised from 10 to 50, and the results accordion, copy and requery controls now track `isFetching` as well as `isLoading`.
- `hyperglass/models/config/params.py` sub-models switched to `Field(default_factory=...)`, so the `cache`, `docs`, `logging`, `messages`, `structured` and `web` blocks no longer share mutable class-level instances.
- The UI build timeout default was raised from 180 to 600 seconds, and `HYPERGLASS_UI_BUILD_TIMEOUT` is now always honoured rather than only when it exceeds the default.
- The credit shown in the footer now identifies this deployment as a fork, giving the fork version, the upstream version it is based on, and a link to the fork repository.
- The group filter row on the query form is hidden when there are no groups to filter by.
- `HyperglassState.clear()` scans and deletes only keys under the `hyperglass.state` namespace instead of flushing the Redis database, so hyperglass no longer deletes keys belonging to anything else sharing that database. Two hyperglass instances sharing one database still share the namespace and will clear each other on start; give each its own `HYPERGLASS_REDIS_DB`.
- The Docker Compose healthcheck queries `/api/info`, which reads Redis-backed state, rather than the UI root, which does not and so reported healthy through a total query outage. `start_period` is raised to 180s to cover the boot-time UI build. Note that Docker Compose does not restart a container for being unhealthy; the healthcheck reports the outage, the in-app rebuild resolves it.

### Fixed

- `HYPERGLASS_WORKERS` is now read. `HyperglassSettings` gained a real `workers` field and the old `workers` property was renamed `worker_count`, returning the explicit value (clamped to at least 1) when set, 1 in debug mode, and twice the CPU count otherwise. A 24-core host no longer unconditionally starts 48 workers.
- Requests arriving before Redis-backed state is populated at startup no longer return 500. State lookups retry up to five times at half-second intervals, and only for retryable attributes, so a genuine attribute error still raises immediately.
- **Configuration state lost from Redis while hyperglass is running is now rebuilt in place.** All runtime configuration was written to Redis once, by `run()` at startup, and never rewritten. Redis is deliberately cache-only, so anything that emptied it (a `FLUSHDB`, or a replaced Redis container, which Docker Compose recreates on its own whenever that image changes) left every state-touching request raising `StateError` until hyperglass was restarted. The `HyperglassState` properties now re-run `init_user_config()` and re-register the plugins under a Redis lock, so one process rebuilds and the others wait for it rather than all re-reading the configuration, with a cooldown so a configuration that cannot be loaded is not re-validated on every request. The recovery sits on the properties rather than on `use_state`, because `Query.device` and the query route read `state.devices` and `state.params` directly off a state instance on every request and never pass through `use_state`; that is the path that fails in production. The plugin registry lives in the same store and is restored with it, otherwise hyperglass comes back but silently stops parsing device output into structured results.
- `init_user_config()` writes a `generation` UUID last, so its presence means state is complete, and a rebuilt store is distinguishable from the original. Exposed as `HyperglassState.generation` and logged at startup.
- The Docker image builds again. The UI stage patched npm's bundled `glob` with `npm --prefix /usr/lib/node_modules/npm install glob@11.1.0`, which cannot succeed: installing into npm's own tree makes npm reconcile npm's `package.json`, whose devDependencies include the unpublished `@npmcli/docs`, so the install returns 404. The patch is also no longer needed, because the npm shipped by the Alpine base image bundles glob 13.x.
- MikroTik RouterOS 7.21 BGP output parses correctly. Active and filtered status is derived from the `contribution` field with the legacy flag column as a RouterOS 6 fallback, terminal-wrapped community lists are de-wrapped before tokenising, `.ext-communities` is parsed, and the flags legend is matched precisely so commented route lines are no longer swallowed.
- Empty MikroTik BGP tables are retried up to four times at ten-second intervals, guarded so that only MikroTik BGP queries with a zero-route structured result retry.
- MikroTik queries no longer return empty. netmiko's `last_read` window is widened to 5 seconds for `mikrotik_routeros` and `mikrotik_switchos`, because RouterOS can take a couple of seconds to begin emitting output for large queries and the default 2-second window returned nothing. This adds roughly 5 seconds to every MikroTik query.
- External RPKI validation no longer runs when `structured.rpki.mode` is `router`. The prefix parse and the external lookup were previously executed in both modes.
- MikroTik traceroute output is aggregated per hop by highest sent count rather than deduplicated by IP, so repeated RouterOS tables no longer produce duplicate or partial hops.

### Security

- Device addressing is no longer leaked to end users. `ScrapeError`, `AuthError`, `RestError` and `DeviceTimeout` strip netmiko's `Device settings:` line, which contained the backend device host and port, from the error text returned by the API and shown in the UI, substituting a generic message when nothing is left.
- Fixable HIGH CVEs flagged by the container scan are patched by floor and override constraints in a new `[tool.uv]` block: brotli 1.2.0+, cryptography 46.0.5+, lxml 6.1.0+, multipart 1.3.1+, Pillow 12.2.0+ (overriding the `pillow<11` cap declared by `favicons`) and psutil 7.1.0 (overriding the `psutil<7` cap declared by `taskipy`).
- Frontend overrides pin `ua-parser-js` to 0.7.36+ for the ReDoS advisory and `@babel/runtime` and `@babel/helpers` to 7.26.10.

### Inherited from upstream

These landed on upstream `main` after 2.0.4 but were never released by upstream. They are present in this fork's code and ship as part of 3.0.0. Credit is upstream's.

- [#280](https://github.com/thatmattlove/hyperglass/issues/280): Fixed `condition: None` causing an error in a directive - @Jimmy01240397
- [#306](https://github.com/thatmattlove/hyperglass/issues/306): Allow integer values in the `ext_community_list_raw` field for Arista BGP - @cooperwinser
- [#311](https://github.com/thatmattlove/hyperglass/issues/311): Fixed device and directive field validation errors
- [#315](https://github.com/thatmattlove/hyperglass/issues/315) and [#187](https://github.com/thatmattlove/hyperglass/issues/187): Fixed the BGP Route query on Huawei NetEngine 8000, via the Huawei BGP route input plugin
- [#325](https://github.com/thatmattlove/hyperglass/pull/325): Fixed code block padding in the documentation - @jagardaniel
- [#332](https://github.com/thatmattlove/hyperglass/pull/332): Fixed custom proxy port support in SSH proxy tunnels - @jessiebryan
- [#245](https://github.com/thatmattlove/hyperglass/issues/245): VyOS platforms moved to the latest LTS command set - @ServerForge
- [#304](https://github.com/thatmattlove/hyperglass/pull/304): FRRouting structured output for BGP routes - @chriswiggins
- [#292](https://github.com/thatmattlove/hyperglass/pull/292): MikroTik BGP route command updated so supernets are selected as well as exact matches - @GrandArcher. Superseded in this fork: the MikroTik BGP route directives were rewritten onto the RouterOS 7 `routing route print detail` syntax, which keeps the supernet behaviour through `{target} in dst-address`.

## 2.0.4 - 2024-06-30

### Fixed

- [#264](https://github.com/thatmattlove/hyperglass/issues/264): Fixed issue where IPv6 traceroutes fail on Juniper devices due to `traceroute: wait must be >1 sec.` error. Thanks @renatoornelas!
- [#267](https://github.com/thatmattlove/hyperglass/issues/267): Fixed issue where responses were incorrectly cached, resulting in no data being shown in the AS Path viewer.
- [#268](https://github.com/thatmattlove/hyperglass/issues/268): Fixed issue where some Mikrotik commands failed to execute properly.
- [#269](https://github.com/thatmattlove/hyperglass/issues/269): Updated documentation regarding `structured.rpki.mode`.
- Removed unnecessary logging statements which caused logging errors.
- Fixed issue where validation of structured BGP route data may have failed under certain conditions.

### Changed
- Error responses are no longer cached.

## 2.0.3 - 2024-06-16

### Fixed

- [#262](https://github.com/thatmattlove/hyperglass/issues/262): Fix issue where Mikrotik output was improperly parsed and displayed an error as a result.
- Fixed issue where incorrect error styles were displayed.
- Fixed issue where 'results' accordion component did not re-open when closed.
- Fixed issue where pattern-based directive rules failed validation.

### Changed

- Set default logo width (back) to 50%, adjusted how the `web.logo.width` setting is handled in the UI.

## 2.0.2 - 2024-06-01

### Fixed

- [#257](https://github.com/thatmattlove/hyperglass/issues/257): Fix issue where if `web.location_display_mode` is set to `dropdown` (automatically or otherwise), the menu would remain open but become detached from the main element because the Query Type element came into view.
- [#253](https://github.com/thatmattlove/hyperglass/issues/253): _Actually_ fix issue where configuration values were improperly prepended with the `HYPERGLASS_APP_PATH` value.
- [#258](https://github.com/thatmattlove/hyperglass/issues/258): Center logo alignment on small screens.
- Fix broken license link in default credit menu.

### Added

- Added license to docs.
- [#254](https://github.com/thatmattlove/hyperglass/issues/254): Users may specify their own DNS over HTTPS provider if desired.

## 2.0.1 - 2024-05-31

### Fixed
- [#244](https://github.com/thatmattlove/hyperglass/issues/244): Fix issue with UI build where UI build directory already existed and therefore could not be created.
- [#249](https://github.com/thatmattlove/hyperglass/issues/249): Fix issue where configuration values were improperly prepended with the `HYPERGLASS_APP_PATH` value.
- [#251](https://github.com/thatmattlove/hyperglass/issues/251): Fix issue where browser-based DNS resolution did not show, causing FQDN queries to fail due to validation.
- Fix issue where logo was improperly sized on small screens.

## 2.0.0 - 2024-05-28

_v2.0.0 is a major release of hyperglass. Many things have changed, and it is likely best to redeploy hyperglass in a new environment to migrate to v2._

### Added

- Commands are now defined as [directives](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/configuration/directives.mdx), which is a configuration definition of one or more commands to run on a device. A directive defines:
  - What command (or commands) to run on the device
  - Type of UI field, text input or select
  - If the field can accept multiple values
  - Help information to show about the directive
  - Validation rules
- hyperglass now supports Docker, and using Docker is the default and recommended method for deployment.
- The list of locations (devices) is displayed as a gallery when the number of devices is 5 or less. This is a default value and is configurable.
- hyperglass now supports custom [input or output plugins](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/plugins.mdx).
  - Input Plugins: Apply custom validation logic or transform user input before the query is sent to a device.
  - Output Plugins: Interact with the output from a device before it's displayed to the user.
- [#206](https://github.com/thatmattlove/hyperglass/issues/206): OpenBGPD is natively supported by hyperglass.
- [#176](https://github.com/thatmattlove/hyperglass/issues/176): Custom javascript or HTML can be injected into the web page (for tracking applications such as Google Analytics).
- [#173](https://github.com/thatmattlove/hyperglass/issues/173): Any output, such as BGP Communities, can be highlighted in the UI by defining [highlight patterns](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/configuration/config/web-ui.mdx#highlighting).
- [#155](https://github.com/thatmattlove/hyperglass/issues/155): A user can now use the "My IP" button to insert their own IP into the query target field.
- [#143](https://github.com/thatmattlove/hyperglass/issues/143): Any HTTP endpoint may be configured as device from which to collect output.

### Fixed
- [#229](https://github.com/thatmattlove/hyperglass/issues/229): Fixed an issue where the logo was not visible when using Firefox.
- [#180](https://github.com/thatmattlove/hyperglass/issues/180): Fixed an issue where certain FQDNs were considered invalid.
- [#178](https://github.com/thatmattlove/hyperglass/issues/178): Fixed an issue where parsing of Arista EOS routes failed if MED is unset.
- [#145](https://github.com/thatmattlove/hyperglass/issues/145): Fixed an issue where menu links were improperly generated.

## 1.0.4 - 2021-07-03

### Fixed
- [#148](https://github.com/thatmattlove/hyperglass/issues/148): Update Debian/Ubuntu Python package name in installer and documentation.
- [#151](https://github.com/thatmattlove/hyperglass/issues/151): Fix issue with Junos structured output parsing from d1160fe where hyperglass would always query both IPv4 and IPv6 for any query type.

### Changed
- Improve handling of Junos XML errors. When a Junos device returns an error in the XML output, it will be displayed in the UI.
- Improve `hyperglass system-info` output. NodeJS version is now included in the output.

## 1.0.3 - 2021-06-23

_1.0.3 is a cosmetic release to factor in code-level changes related to the repository name change from checktheroads to thatmattlove._

## 1.0.2 - 2021-06-18

### Fixed
- [#150](https://github.com/thatmattlove/hyperglass/issues/150): Fix handling of BIRD AS_PATH/Community targets.

## 1.0.1 - 2021-06-17

### Fixed
- UI: fix body overflow issue

## 1.0.0 - 2021-05-30

### BREAKING CHANGES
- The `external_link`, `help`, and `terms` parameters no longer exist and have been replaced with generic `links` and `menus` options.
- The transitionary `frr_ssh` and `bird_ssh` NOS parameters no longer exist — `frr` and `bird` can now be used for SSH-based connectivity. hyperglass-agent users must now use `frr_legacy` and `bird_legacy` until hyperglass-agent is fully deprecated.

### Fixed
- [#139](https://github.com/thatmattlove/hyperglass/issues/139): Fix an issue where the API cannot be queried by device name.

### Changed
- Updated UI dependencies

### Added
- [#140](https://github.com/thatmattlove/hyperglass/issues/140): Genericize links and menus so that multiple links and/or menus can be defined and fully customized.

## 1.0.0-beta.82 - 2021-04-22

### BREAKING CHANGE
**NodeJS 14.15 or later is required**. See the [installation documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/installation/manual.mdx) for installation instructions.

### Fixed
- [#135](https://github.com/thatmattlove/hyperglass/issues/135): Fix an issue where Juniper indirect next-hops were empty.
- Fix an issue where Juniper structured AS_PATH or Community queries would appear to fail if one address family (IPv4 or IPv6) had an empty response. For example, if an AS_PATH query for `.* 29414 .*` was made (which only returns IPv4 routes), the query would fail.

### Changed
- Updated major Python dependencies (FastAPI, Scrapli, Netmiko, Pydantic, Uvicorn, Gunicorn, etc.)
- Updated UI dependencies
- [#128](https://github.com/thatmattlove/hyperglass/pull/128): Add `best` to all Juniper BGP Route queries. See [Juniper docs](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/ref/command/show-route-best.html) for more details.

### Added
- The driver for devices can now be overridden with the `driver` parameter.

## 1.0.0-beta.81 - 2021-04-10

### Fixed
- [#124](https://github.com/thatmattlove/hyperglass/issues/124): Fix an issue where networks weren't always sorted alphabetically.
- [#126](https://github.com/thatmattlove/hyperglass/issues/126): Fix rendering of markdown tables.
- [#132](https://github.com/thatmattlove/hyperglass/issues/132): Fix an issue where iBGP routes on Arista devices caused output parsing to fail.
- [#133](https://github.com/thatmattlove/hyperglass/issues/133): Use body styles for background/foreground color, allowing the user to override the `light` and `dark` colors per the docs.
- Fix an issue with select menu list style.

### 1.0.0-beta.80 - 2021-03-03

### Fixed
- Fix an issue where the UI did not properly filter and detect the correct Query VRF when only one was defined.
- [#121](https://github.com/thatmattlove/hyperglass/issues/121): Fix issue with select menu styling in light mode.

### 1.0.0-beta.79 - 2021-02-26

### BREAKING CHANGE
**Major changes have been made to how VRFs are defined and handled.** Previously, you would signal to hyperglass that a VRF was the "default" VRF (meaning, a VRF does not need to be specified in any commands) by setting `name: default` in the VRF block. This limitation meant that a VRF named `default` _had_ to be defined, and that any users who keep their global routing table in a non-default VRF must define it separately.

Moving forward, the `name` field is only used to define the name of the VRF **as known by the device**. To signal that hyperglass should use the device's default VRF, set `default: true` on the VRF. **This is not the default**.

### Fixed
- Fix an issue where long-running commands, such as traceroutes that never complete, time out and display an error instead of the output.

### Changed
- Don't do external RPKI lookups for non global unicast prefixes.
- Migrate to palette-by-numbers for theming.
- Update UI dependencies.

### 1.0.0-beta.78 - 2021-02-12

### Added
- Experimental table output/structured data support for Arista EOS.

### Fixed
- Corrected warning color on active routes in table output.

### Changed
- Caught fetch errors now display the HTTP status text in the UI, instead of the caught error message.

### 1.0.0-beta.77 - 2021-02-10

**POTENTIALLY BREAKING CHANGE**: The device `display_name` field is being deprecated, in favor of a single `name` field, which will be displayed to the end user. The `display_name` field still works, but you should migrate away from it as soon as possible.

### Fixed
- [#117](https://github.com/thatmattlove/hyperglass/issues/117): Fix naming and mapping of the Arista EOS driver. `arista` and `arista_eos` will both work now.

### Changed
- Removed `display_name` field from device model. The `name` field will be used in the UI. If a `display_name` is defined, it will be used, for backwards compatibility.

### 1.0.0-beta.76 - 2021-02-06

**NOTICE**: *[hyperglass-agent](https://github.com/thatmattlove/hyperglass-agent) will be deprecated soon. Use `frr_ssh` or `bird_ssh` for SSH connectivity in the meantime.*

### Added
- FRR & BIRD may now be accessed via standard SSH using the `frr_ssh` and `bird_ssh` NOS. See the [platform documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/platforms.mdx) for important caveats.

### Changed
- `port` in `devices.yaml` now defaults to 22 if not specified.

### Fixed
- AS Path graph view now uses [dagre](https://github.com/dagrejs/dagre) to properly arrange each AS.
- Added timeout argument to `hyperglass start --build` - fixes issue where running a UI build in this way failed due to a missing timeout argument error.

### 1.0.0-beta.75 - 2021-01-28

### Changed
- Default UI build timeout is now 180 seconds.
- The hyperglass `build-ui` CLI command now accepts a `--timeout` argument to override the UI build timeout.

### 1.0.0-beta.74 - 2021-01-25

### Changed
- The Scrapli driver no longer specifically ignores the system's SSH config file.
- Updated UI dependencies.

### Fixed
- [#109](https://github.com/thatmattlove/hyperglass/issues/109): Remove the custom error page, because it doesn't work and doesn't really add much.

### 1.0.0-beta.73 - 2021-01-18

### Added
- [#106](https://github.com/thatmattlove/hyperglass/issues/106): Add built-in support for Nokia SR OS (thanks @paunadeu!).

### Changed
- [#105](https://github.com/thatmattlove/hyperglass/issues/105): Check NodeJS version on startup to ensure the minimum supported version is present.
- Update UI dependencies.

### Fixed
- [#107](https://github.com/thatmattlove/hyperglass/issues/107): Fix footer menu styling so it doesn't overflow the viewport, especially on mobile.

### 1.0.0-beta.72 - 2021-01-16

### Fixed
- [#104](https://github.com/thatmattlove/hyperglass/issues/104): Handle the usage of `juniper_junos` as a NOS. `juniper_junos` will now automatically be mapped to `juniper`.
- Fix an issue with dual RP juniper devices and structured output, where output containing `{master}` outside of the XML output was improperly stripped out, causing a parsing failure.

### Changed
- **BREAKING**: The installer no longer generates a Systemd service file. While this was likely convenient for most, it introduced significant complexity and caused most installations using `~/hyperglass` as the app path to fail, with no clear way to resolve it. Further, while Systemd is arguably the most common, it is not the *only* process manager available. As such, the docs will be updated with a Systemd example, much like the current reverse proxy documentation.

### 1.0.0-beta.71 - 2021-01-10

### Added
- Added Google Analytics Support. Use the `google_analytics` field for the tracking ID in `hyperglass.yaml`.

### Changed
- Minor frontend code improvements.

### 1.0.0-beta.70 - 2021-01-05

### Fixed

- [#100](https://github.com/thatmattlove/hyperglass/issues/100): Fix result panel bug where incorrect panels would open, or panels would not open at all. Resolved by accessing internal state of the `Accordion />` component via `useAccordionContext()` instead of directly changing the index prop via state.

### Changed
- Query results now automatically cancel when each result panel unmounts (e.g. when one clicks the back button).

### 1.0.0-beta.69 - 2021-01-03

### Fixed

- Fix Safari browser-specific issues
- Setup no longer fails when `commands.yaml` doesn't exist, even though it isn't needed.

### Changed

- Setup no longer adds example files

### 1.0.0-beta.67 - 2021-01-02

### Fixed

- Fix handling of `web.theme.default_color_mode`. Starting in 1.0.0-beta.65, it was completely ignored and used the library's default of `light`. Now, it's handled properly.
- Fix table output layout issues, particularly on mobile.

### 1.0.0-beta.66 - 2021-01-02

### Fixed

- Fixed Safari browser-specific issues
- Fixed mobile layout issues

### Changed

- `web.theme.colors.black` and `web.theme.colors.white` are now `web.theme.colors.dark` and `web.theme.colors.light respectively`

### 1.0.0-beta.65 - 2021-01-01

### Added

- [#72](https://github.com/thatmattlove/hyperglass/issues/72): _EXPERIMENTAL_ BGP map support for devices supporting structured output (Juniper Junos, currently).

### Fixed

- Fix an issue causing Juniper Junos BGP output parsing to fail if the XML output contains a banner.

### Changed

- `web.text.title` and `web.text.subtitle` now carry a 32 character limit for simpler styling.
- Various UI layout, styling improvements, and stability improvements.

### 1.0.0-beta.63 - 2020-10-18

### Added

- [#87](https://github.com/thatmattlove/hyperglass/issues/87): [TNSR] Support. To add a TNSR device, use the `tnsr` platform configuration described in the [platform documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/platforms.mdx).

### Fixed

- Fix an issue causing hyperglass custom exceptions to not be properly raised, which caused more generic error messages in the UI/API.

### 1.0.0-beta.62 - 2020-10-17

### Fixed

- Fix an issue causing exceptions not to be logged to the log file (but logged to stdout).

### 1.0.0-beta.61 - 2020-10-11

### POTENTIALLY BREAKING CHANGE

When hyperglass starts up, it will check to see if `~/hyperglass` or `/etc/hyperglass/` exists. Previously, it would silently choose the first one found, even if both exist. Now, if both exist, an exception is raised with instruction to delete one of them. If your system has both directories, hyperglass may not start up normally after you upgrade.

### Fixed

- Fix a DNS resolution issue which caused Debian systems to be unable to resolve the hostnames of any devices. This was due to differences in how the Python socket module works on Debian vs other distros (even Ubuntu).

### Added

- [#81](https://github.com/thatmattlove/hyperglass/issues/81): Add support for SSH key authentication. See the [credential documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/configuration/devices/credentials.mdx) for more details.

### 1.0.0-beta.60 - 2020-10-10

### Fixed

- [#90](https://github.com/thatmattlove/hyperglass/issues/90): Fix a typing error that caused ping & traceroute queries to fail for certain devices.

### Added

- [#82](https://github.com/thatmattlove/hyperglass/issues/82): Add support for Redis password authentication. Authentication can be configured in the following manner:

```yaml
# hyperglass.yaml
cache:
  password: examplepassword
```

This would correspond with the following stanza in the Redis configuration file:

```
requirepass examplepassword
```

### 1.0.0-beta.59 - 2020-10-05

### Added

- Native Mikrotik support.
- `hyperglass clear-cache` command for easy manual clearing of the Redis cache.

### Changed

- Improve output parsing scalability - parsers can now be defined on a per-NOS basis regardless of whether or not structured-data is used.
- Restructure model locations & importing to remove some complexities.

### 1.0.0-beta.58 - 2020-09-28

### Changed

- [#79](https://github.com/thatmattlove/hyperglass/issues/79): Run the UI build on startup & clarify docs.
- Removed all f-strings from log messages.
- Migrate icon library to [@meronex/icons](https://github.com/meronex/meronex-icons) for better tree-shaking.
- Improve console (stdout) logging
- Fix file logging format

### Fixed

- [#74](https://github.com/thatmattlove/hyperglass/issues/74): Fix UI build failures caused by `.alias.js`.
- [#75](https://github.com/thatmattlove/hyperglass/issues/75): Fix whitespace stripping of query target.
- [#77](https://github.com/thatmattlove/hyperglass/issues/77): Allow dashes in FQDN validation pattern.
- [#83](https://github.com/thatmattlove/hyperglass/issues/83): Fix lack of support for `protocol-nh` field in Juniper XML BGP table.

### 1.0.0-beta.57 - 2020-07-30

### BREAKING CHANGE

If you use [hyperglass-agent](https://github.com/thatmattlove/hyperglass-agent), you must upgrade your version of hyperglass-agent to 0.1.6 or later. If using hyperglass-agent with SSL, this release will require you to re-generate & re-send your SSL certificates to hyperglass:

```console
$ hyperglass-agent certificate
$ hyperglass-agent send-certificate
```

### Changed

- Verify a device's address is either an IPv4 or IPv6 address, or a resolvable hostname.
- Devices using hyperglass-agent (FRR, BIRD) no longer need to use a DNS-resolvable hostname in the `address:` field, as long as the certificate has been generated by hyperglass-agent, and the proper IP addresses were selected during the prompts to generate the certificate. _If using your own certificate and you want to connect to hyperglass-agent via an IP address instead of a hostname, you need to ensure the IP address of hyperglass-agent is listed as a Subject Alternative Name in the certificate extensions._
- Refactored device, query, proxy models to no longer scrub unsupported characters from the device name for the purposes of Python class attribute accessing.
- Updated hyperglass-agent docs.

### 1.0.0-beta.56 - 2020-07-28

### Changed

- Improved Gunicorn address formatting.
- Improved Redis connection error handling.

### Fixed

- [#56](https://github.com/thatmattlove/hyperglass/issues/56): Fix a silent Redis connection error if the Redis server was anything other than `localhost`, preventing hyperglass from starting.

### 1.0.0-beta.55 - 2020-07-27

### Changed

- Removed JS favicon build process in favor of native Python implementation ([favicons](https://github/thatmattlove/favicons))

### 1.0.0-beta.54 - 2020-07-25

### Fixed

- Queries to hyperglass-agent devices failed due to the error `AttributeError: 'AgentConnection' object has no attribute 'collect'`

### 1.0.0-beta.53 - 2020-07-23

### Added

- **BREAKING CHANGE**: [Scrapli](https://github.com/carlmontanari/scrapli) is now used for SSH connectivity to Cisco IOS, Cisco IOS-XE, Cisco IOS-XR, Cisco NX-OS Juniper Junos, and Arista EOS, which should improve the speed at which output is gathered from devices. _As of this release, Cisco IOS/IOS-XE and Juniper Junos have been directly tested and worked without issue. However, if you discover any anomalies with any of these operating systems, please [open an issue](https://github.com/thatmattlove/hyperglass/issues)._

### Changed

- Refactor of SSH & HTTPS command execution to enable pluggable underlying driver capabilities.
- Remove `aiofile` dependency by removing unnecessary asyncio file operations in the UI build process.
- Added `scrapli[asyncssh]` dependency for Scrapli driver support.

### Fixed

- UI: Error messages couldn't be copied with the copy button

### 1.0.0-beta.52 - 2020-07-19

### Added

- API route `/api/info`, which displays general system information such as the name of the organization and version of hyperglass.
- API docs configuration parameters for the `/api/info` route.
- [#63](https://github.com/thatmattlove/hyperglass/issues/63): Minimum RAM requirements.
- `hyperglass system-info` CLI command to gather system CPU, Memory, Disk, Python Version, hyperglass Version, & OS info. _Note: this information is only gathered if you run the command, and even then, is printed to the console and not otherwise shared or exported_.

### Changed

- Updated docs dependencies.
- Improved YAML alias & anchor docs.
- [#55](https://github.com/thatmattlove/hyperglass/issues/55): Removed YAML alias & anchors from default examples to avoid confusion.

### Fixed

- API docs logo URL now displays correctly.
- [#62](https://github.com/thatmattlove/hyperglass/issues/62): Added `epel-release` to CentOS installation instructions.
- [#59](https://github.com/thatmattlove/hyperglass/issues/59): Fixed copy output for Juniper devices on non-table output query types.
- [hyperglass-agent #6](https://github.com/hyperglass-agent/issues/6): Fixed hyperglass-agent documentation issues.
- Improve command customization docs.
- [#61](https://github.com/thatmattlove/hyperglass/issues/61): Fixed copy output for table data. Output is now a bulleted list of parsed data.

### 1.0.0-beta.51 - 2020-07-13

### Changed

- Improved config import process & error handling.
- Improved logging initialization so that noisy logs aren't generated on startup unless debugging is enabled.

### Fixed

- [#54](https://github.com/thatmattlove/hyperglass/issues/54): A Junos parsing error caused routes with no communities to raise an error.
- Pre-validated config files are no longer logged on startup unless debugging is enabled.

### 1.0.0-beta.50 - 2020-07-12

### Added

- Synchronous API for Redis caching.
- New `redis-py` dependency for synchronous Redis communication.

### Changed

- Improved cache type conversion when reading cached data.
- External data via [bgp.tools](https://bgp.tools) is now gathered via their bulk mode API.
- External data via [bgp.tools](https://bgp.tools) is now cached via Redis to reduce external traffic and improve performance.
- RPKI validation via [Cloudflare](https://rpki.cloudflare.com/) is now cached via Redis to reduce external traffic and improve performance.
- Update Python dependencies.

### Fixed

- [#54](https://github.com/thatmattlove/hyperglass/issues/54): A Junos structured/table output parsing error caused routes with multiple next-hops to raise an error.
- RPKI validation no longer occurs twice (once on serialization of the output, once on validation of the API response).

### 1.0.0-beta.49 - 2020-07-05

### Changed

- Update UI dependencies
- Removed react-textfit in favor of responsive font sizes and line breaking
- Refactor & clean up React components

### Fixed

- Route lookups for private (RFC 1918) addresses failed due to an unnecessary lookup to [bgp.tools](https://bgp.tools)

### 1.0.0-beta.48 - 2020-07-04

### Added

- New NOS: **VyOS**. See the [platform documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/platforms.mdx) for important caveats.

### Fixed

- UI: If the logo `width` parameter was set to ~ 50% and the `title_mode` was set to `logo_subtitle`, the subtitle would appear next to the logo instead of underneath.
- When copying the opengraph image, the copied image was not deleted.
- Default traceroute help link now _actually_ points to the new docs site.

### 1.0.0-beta.47 - 2020-07-04

### Added

- Opengraph images are now automatically generated in the correct format from any valid image file.
- Better colour mode toggle icons.

### Changed

- Improved SEO & Accessibility for UI.
- Default traceroute help link now points to new docs site.
- Slightly different default black and white colours.
- Various docs site improvements

### Fixed

- Remove `platform.linux_distribution()` which was removed in Python 3.8
- Width of page is no longer askew when `logo_subtitle` is set as the `title_mode`
- Generated favicon manifest files now go to the correct directory.
- Various docs site fixes

### 1.0.0-beta.46 - 2020-06-28

### Added

- Support for hyperglass-agent [0.1.5](https://github.com/thatmattlove/hyperglass-agent)

### 1.0.0-beta.45 - 2020-06-27

### Changed

- Removed RIPEStat for external data gathering, switched to [bgp.tools](https://bgp.tools)

### Fixed

- Webhook construction bugs that caused webhooks not to send
- Empty response handling for table output

### 1.0.0-beta.44 - 2020-06-26

### Added

- Support for Microsoft Teams webhook

### Fixed

- If webhooks were enabled, a hung test connection to RIPEStat would cause the query to time out

### 1.0.0-beta.43 - 2020-06-22

### Fixed

- Logo path handling in UI

### 1.0.0-beta.42 - 2020-06-21

### Added

- Automatic favicon generation

### Changed

- **BREAKING CHANGE**: The `logo` section now requires the full path for logo files. See the [web UI configuration documentation](https://github.com/WilhelmZA/ultraglass/blob/main/docs/content/configuration/config/web-ui.mdx) for details.
