# Contributing to Ultraglass

Ultraglass is maintained as a fork of hyperglass. Contributions are welcome when they improve the application without making existing deployments harder to operate or breaking the compatibility namespace used by the Python package and CLI.

## Before opening a pull request

- Read the relevant documentation and tests before changing behaviour.
- Explain the user-visible problem and the approach taken to solve it.
- Add or update tests for behaviour that can be tested automatically.
- Update the documentation when configuration, installation, or user-visible behaviour changes.
- Remove credentials, tokens, private keys, and private network details from examples and issue reports.

## Development standards

- Format Python with Black and keep imports ordered with isort.
- Keep Ruff and the frontend lint, formatting, type, and test checks clean.
- Keep text visible to administrators and users configurable unless there is a clear reason not to.
- Keep the UI usable on desktop and mobile and preserve accessible labels and controls.
- Include IPv6 handling when adding or changing network device support.
- Keep device queries non-blocking and avoid introducing work on the event loop that can wait on a network device.
- Keep public documentation factual and include the exact commands needed to reproduce an installation or bug.

## Local checks

The backend tests require Redis on `localhost:6379`:

```shell
pytest hyperglass --ignore hyperglass/plugins/external
```

The UI checks run from `hyperglass/ui`:

```shell
pnpm install --frozen-lockfile
pnpm run format:check
pnpm run lint
pnpm run typecheck
pnpm run test
```

The internal Python package and CLI remain named `hyperglass`. Do not rename imports, environment variables, configuration paths, service names, or CLI commands as part of a documentation or public-brand change unless the change explicitly includes a migration plan.
