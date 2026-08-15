# terraform-provider-mcpg

A native Terraform provider for MCPG that manages `mcpg.dev` custom resources
directly against the operator plane, and — its distinctive value over plain
manifest application — **validates them at `terraform plan`** using the same
rules the operator's admission webhook enforces. Bad input fails locally, with
the offending rule named, before anything reaches the API server. Written in Go
on the Terraform Plugin Framework; it runs under Terraform and OpenTofu alike.

## Prerequisites

- A Kubernetes cluster running the MCPG operator, with the `mcpg.dev` CRDs
  installed, and a kubeconfig that can reach it.
- Terraform ≥ 1.7 or OpenTofu ≥ 1.7.
- Go 1.26 or newer, to build from source.

## Quick start

```hcl
terraform {
  required_providers {
    mcpg = { source = "mcpg-dev/mcpg" }
  }
}

provider "mcpg" {
  kubeconfig = "~/.kube/config" # optional; falls back to KUBECONFIG / in-cluster
  context    = "prod"           # optional kubeconfig context
}

resource "mcpg_gateway" "orders" {
  name      = "orders"
  namespace = "mcpg-system"
  spec = jsonencode({
    image    = { repository = "ghcr.io/mcpg-dev/source-code/gateway", tag = "<version>" }
    replicas = 2
    config = {
      governance = { audit = { sinks = [{ kind = "dev.mcpg.builtin.audit.local-file" }] } }
    }
  })
}

resource "mcpg_revocation_list" "default" {
  name = "cluster-default"
  spec = jsonencode({
    version     = 1
    revocations = [{ artifactSha256 = "…64 hex…", reason = "compromised" }]
  })
}
```

The `config` object inside a gateway `spec` is the gateway's own application
configuration; the operator passes it through unchanged.

## Resources

Every resource shares one shape: a typed kind whose `spec` is supplied as JSON.
Creates use the field manager `terraform-provider-mcpg`; updates go through
server-side apply with conflicts forced, so the provider owns the fields it
writes and leaves the operator's own status and defaulted fields alone.

| Resource | Kind | Scope |
|---|---|---|
| `mcpg_gateway` | `MCPGGateway` | namespaced |
| `mcpg_plugin_set` | `MCPGPluginSet` | namespaced |
| `mcpg_route` | `MCPGRoute` | namespaced |
| `mcpg_plugin` | `MCPGPlugin` | cluster |
| `mcpg_revocation_list` | `MCPGRevocationList` | cluster |
| `mcpg_cluster` | `MCPGCluster` | cluster |
| `mcpg_tenant` | `MCPGTenant` | cluster |
| `mcpg_plugin_mirror` | `MCPGPluginMirror` | cluster |

A read that cannot fetch the object removes it from state rather than failing,
so a resource deleted out of band is planned for recreation on the next run.

## Plan-time validation

Each resource implements `ValidateConfig`, so `terraform plan` reports admission
violations without a cluster round trip. A namespaced kind with no `namespace`
is an error on that attribute; a `spec` that is not valid JSON is an error on
`spec`; and every rule violation becomes its own attribute error whose summary
is the stable rule id — `plugin.trust.anchor`, `gateway.workloadIdentity.oneOf`,
`revocationList.noDuplicates`, and so on.

The checks cover every kind in the table above: gateway image, replica floor, one-of workload
identity and ingress shape; plugin id, class, version, OCI reference, the
digest-or-cosign trust anchor, the mandatory Ed25519 `signingKeyRef`, and the
anchored cosign `certificateIdentityRegexp`; plugin-set entry ids and capability
grants; revocation-list version, hex hashes, reasons and duplicates; cluster
backend config and plaintext-transport refusal; route gateway reference, tool
ids and chains; tenant namespaces, plugin matchers and quotas; and plugin-mirror
endpoint and upstream shape.

Cross-resource and client-backed admission checks stay on the server, by design:
the per-tenant replica cap and plugin allowlist need cluster state, and
`image.tag` is filled in by the mutating webhook, so rejecting an absent tag at
plan time would break the rely-on-defaulting path. Plan-time validation is a
high-coverage local gate, not a guarantee of admission acceptance.

`internal/validators` is a port of the MCPG Pulumi CrossGuard validators, and a
shared fixture corpus asserts both sides produce identical verdicts, so a rule
relaxed on one side fails the build. `cmd/contract-check` exposes the same logic
as a one-shot binary — give it a resource type token (anything ending in
`:<Kind>`) and a spec JSON, and it prints the JSON array of violated rule ids:

```bash
go run ./cmd/contract-check k8s:mcpg.dev/v1alpha1:MCPGGateway '{}'
# ["gateway.image.required"]
```

## Configuration

### Provider arguments

Authentication follows the standard kubeconfig chain: an explicit path, then the
default loading rules (including `KUBECONFIG`), then in-cluster credentials.

| Parameter | Description | Default |
|---|---|---|
| `kubeconfig` | Path to a kubeconfig file. | unset — default loading rules |
| `context` | kubeconfig context to select. | unset — current context |

### Resource attributes

| Parameter | Description | Default |
|---|---|---|
| `name` | Resource name. Required. | — |
| `namespace` | Required for namespaced kinds; ignored for cluster-scoped ones. | — |
| `spec` | The CR spec as JSON. Required — build it with `jsonencode`. | — |
| `id` | Computed: `namespace/name`, or `name` for cluster-scoped kinds. | computed |
| `config_hash` | Computed: the operator's `status.configHash`, when present. A drift signal you can key downstream resources off. | computed |

## Build and test

```bash
go build -o terraform-provider-mcpg .
go test ./...
test -z "$(gofmt -l .)" && go vet ./...
```

CI runs the same checks: `go build ./...`, `go test ./...`, and
`gofmt -l . && go vet ./...`.

To exercise a local build, point your Terraform CLI configuration at the binary
with a `dev_overrides` block for `mcpg-dev/mcpg`.

## Licence

Apache-2.0.

## See also

- <https://mcpg.dev/docs/self-hosting/terraform-provider> — the provider guide.
- <https://mcpg.dev/docs/self-hosting/terraform> — the HCL module suite, which
  covers the common case with no provider install and can be mixed with this
  provider.
- <https://mcpg.dev/docs/reference/operator-crds> — the `mcpg.dev` CRDs these
  resources map onto.
- <https://mcpg.dev/docs/reference/configuration> — the gateway configuration
  schema that goes inside a gateway `spec.config`.
