# keymanager

TPM 2.0-backed key and certificate management for Sovereignite nodes. Extracted
from [`github.com/sovereignite/sovereignite`](https://github.com/sovereignite/sovereignite)
(`internal/keymanager` + `cmd/keymanager`).

The root package `keymanager` manages persistent TPM key objects and
certificate profiles: it provisions per-role persistent handles, enforces
key-role policies (purpose, algorithm, rotation interval, lifetime vs.
operational), issues CA-signed certificates via the TPM, and crash-recovers a
versioned metadata store written to disk. The `cmd/keymanager` binary exposes
the manager as a long-running service (plus an `initialize` one-shot mode) with
a `--tpm-device` and `--metadata-path` interface.

The only non-stdlib dependency is the sibling
[`github.com/sovereignite/tpm`](https://github.com/sovereignite/tpm) module,
resolved via a local `replace` directive until it is published.

## Build & test

```sh
go build ./...
go test ./...
```

## Deploy

- `kubernetes/sovereignite.io/keymanager/` — kustomize manifests (DaemonSet,
  namespace, service account).
- `.ko.yaml` — ko build entry (`main: ./cmd/keymanager`, static, `CGO_ENABLED=0`).
- `os/systemd/sovereignite-keymanager.service` — systemd unit.

## License

GPL-2.0-only. See [LICENSE.md](LICENSE.md).
