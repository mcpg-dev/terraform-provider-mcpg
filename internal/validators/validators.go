// Package validators holds the admission-mirror validation logic for the
// Terraform provider's plan-time checks. It is a faithful port of the Pulumi
// CrossGuard validators (iac/pulumi/policy/src/validators.ts) so BOTH offerings
// produce identical accept/reject verdicts against the shared contract corpus
// (iac/contract/). Mirror k8s/operator/src/admission/validators/.
package validators

import (
	"regexp"
	"strconv"
	"strings"
)

// Finding is one validation violation (empty slice = accept).
type Finding struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// The operator accepts any 64 ascii-hexdigit string (case-insensitive) and
// lowercases for dedup — uppercase hashes are valid (adm-2 / trust-5).
var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// IsSha256Hex reports whether s is exactly 64 hex chars (case-insensitive).
func IsSha256Hex(s string) bool { return sha256Re.MatchString(s) }

// knownPluginClasses mirrors mcpg_plugin_protocol::abi::ALL_KINDS.
var knownPluginClasses = map[string]bool{
	"tool_gate": true, "transform": true, "identity_provider": true, "backend": true,
	"watch_strategy": true, "http_route": true, "audit_sink": true, "log_sink": true,
	"telemetry_sink": true, "metrics_sink": true, "store": true, "cache": true,
	"secret_provider": true, "config_provider": true, "policy_engine": true,
	"cluster": true, "transport": true, "catalog_provider": true,
	"credential_issuer": true, "approval_notifier": true, "content_store": true,
}

// IsAnchoredRegexp reports whether s is anchored with ^ and $ and compiles.
func IsAnchoredRegexp(s string) bool {
	if !strings.HasPrefix(s, "^") || !strings.HasSuffix(s, "$") {
		return false
	}
	_, err := regexp.Compile(s)
	return err == nil
}

var workloadIdentityKeys = []string{"aws", "gcp", "azure", "spiffe"}

func countWorkloadIdentities(wi map[string]any) int {
	n := 0
	for _, k := range workloadIdentityKeys {
		if v, ok := wi[k]; ok && v != nil {
			n++
		}
	}
	return n
}

func findDuplicates(items []any, key func(any) string) []string {
	seen := map[string]bool{}
	emitted := map[string]bool{}
	var dups []string
	for _, it := range items {
		k := key(it)
		if seen[k] && !emitted[k] {
			emitted[k] = true
			dups = append(dups, k)
		}
		seen[k] = true
	}
	return dups
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func asSlice(v any) []any        { s, _ := v.([]any); return s }
func asString(v any) string      { s, _ := v.(string); return s }

// asFloat returns the float64 value (JSON numbers decode to float64) and
// whether v was a number.
func asFloat(v any) (float64, bool) { f, ok := v.(float64); return f, ok }

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func itoa(i int) string { return strconv.Itoa(i) }

// ValidateGatewaySpec mirrors the MCPGGateway admission rules.
func ValidateGatewaySpec(spec map[string]any) []Finding {
	var f []Finding
	if spec["image"] == nil {
		f = append(f, Finding{"gateway.image.required", "spec.image is required"})
	}
	// replicas, when set, must be ≥ 1 (gateway.rs:65). Absent ⇒ defaulted ⇒ ok.
	if v, ok := asFloat(spec["replicas"]); ok && v < 1 {
		f = append(f, Finding{"gateway.replicas.min", "spec.replicas must be ≥ 1"})
	}
	if wi := asMap(spec["workloadIdentity"]); wi != nil && countWorkloadIdentities(wi) > 1 {
		f = append(f, Finding{"gateway.workloadIdentity.oneOf", "workloadIdentity must be exactly one of aws|gcp|azure|spiffe"})
	}
	// Ingress sub-shape (gateway.rs:114-130) when an ingress block is present.
	if ing := asMap(spec["ingress"]); ing != nil {
		if blank(asString(ing["ingressClassName"])) {
			f = append(f, Finding{"gateway.ingress.ingressClassName", "spec.ingress.ingressClassName must not be empty"})
		}
		hosts := asSlice(ing["hosts"])
		if len(hosts) == 0 {
			f = append(f, Finding{"gateway.ingress.hosts", "spec.ingress.hosts must not be empty when ingress is set"})
		}
		for i, h := range hosts {
			hm := asMap(h)
			if blank(asString(hm["host"])) {
				f = append(f, Finding{"gateway.ingress.host", "spec.ingress.hosts[" + itoa(i) + "].host is empty"})
			}
			if len(asSlice(hm["paths"])) == 0 {
				f = append(f, Finding{"gateway.ingress.paths", "spec.ingress.hosts[" + itoa(i) + "].paths must not be empty"})
			}
		}
	}
	// NB: image.tag-non-empty (operator-defaulted by the mutating webhook) and
	// the tenant per-gateway replica cap (cross-resource) are intentionally NOT
	// mirrored at plan time.
	return f
}

// ValidatePluginSpec mirrors the MCPGPlugin admission rules.
func ValidatePluginSpec(spec map[string]any) []Finding {
	var f []Finding
	oci := asMap(spec["oci"])
	trust := asMap(spec["trust"])

	// Identity + class + version (plugin.rs:56-83).
	pluginID := asString(spec["pluginId"])
	if blank(pluginID) {
		f = append(f, Finding{"plugin.pluginId.nonEmpty", "spec.pluginId must not be empty"})
	} else if !strings.Contains(pluginID, ".") {
		f = append(f, Finding{"plugin.pluginId.reverseDns", "spec.pluginId is not reverse-DNS form (e.g. dev.mcpg.identity.workload)"})
	}
	if blank(asString(spec["version"])) {
		f = append(f, Finding{"plugin.version.nonEmpty", "spec.version must not be empty"})
	}
	if !knownPluginClasses[asString(spec["pluginClass"])] {
		f = append(f, Finding{"plugin.pluginClass.known", "spec.pluginClass is not a known PluginClass"})
	}

	// OCI image reference shape (plugin.rs:84-99).
	img := strings.TrimSpace(asString(oci["image"]))
	if img == "" {
		f = append(f, Finding{"plugin.oci.image.nonEmpty", "spec.oci.image must not be empty"})
	} else {
		if !strings.Contains(img, "/") {
			f = append(f, Finding{"plugin.oci.image.registry", "spec.oci.image lacks a registry component (<registry>/<path>)"})
		}
		if !strings.Contains(img, ":") && !strings.Contains(img, "@") {
			f = append(f, Finding{"plugin.oci.image.tagOrDigest", "spec.oci.image lacks a tag or digest pin (:tag or @sha256:...)"})
		}
	}

	// Trust anchor: digest pin OR cosign identity (plugin.rs:101-112).
	digestPinned := strings.Contains(img, "@sha256:")
	cosign := asMap(trust["cosignIdentity"])
	hasCosign := cosign != nil
	if !digestPinned && !hasCosign {
		f = append(f, Finding{"plugin.trust.anchor", "plugin must be digest-pinned OR carry a cosign identity"})
	}

	// signingKeyRef (Ed25519) is the MANDATORY baseline (plugin.rs:119-124).
	skr := asMap(trust["signingKeyRef"])
	if blank(asString(skr["secretName"])) {
		f = append(f, Finding{"plugin.trust.signingKeyRef.required", "spec.trust.signingKeyRef.secretName is required (Ed25519 signing is the mandatory trust baseline)"})
	}
	if k, ok := skr["key"]; ok && blank(asString(k)) {
		f = append(f, Finding{"plugin.trust.signingKeyRef.key", "spec.trust.signingKeyRef.key must not be empty when set"})
	}

	// Cosign sub-shape (plugin.rs:126-163).
	if hasCosign {
		if blank(asString(cosign["certificateIdentityRegexp"])) {
			f = append(f, Finding{"plugin.cosign.regexpNonEmpty", "cosign certificateIdentityRegexp must not be empty"})
		} else if !IsAnchoredRegexp(asString(cosign["certificateIdentityRegexp"])) {
			f = append(f, Finding{"plugin.cosign.anchoredRegexp", "cosign certificateIdentityRegexp must be anchored with ^ and $ and compile (RE2)"})
		}
		if blank(asString(cosign["oidcIssuer"])) {
			f = append(f, Finding{"plugin.cosign.oidcIssuer", "cosign oidcIssuer is required when cosign is set"})
		}
	}

	// SLSA provenance sub-shape (plugin.rs:166-178).
	if slsa := asMap(trust["slsaProvenance"]); slsa != nil {
		if blank(asString(slsa["configMapName"])) {
			f = append(f, Finding{"plugin.slsa.configMapName", "spec.trust.slsaProvenance.configMapName must not be empty"})
		}
		if blank(asString(slsa["sourceUri"])) {
			f = append(f, Finding{"plugin.slsa.sourceUri", "spec.trust.slsaProvenance.sourceUri must not be empty"})
		}
		if blank(asString(slsa["sourceTag"])) {
			f = append(f, Finding{"plugin.slsa.sourceTag", "spec.trust.slsaProvenance.sourceTag must not be empty"})
		}
	}
	return f
}

// ValidatePluginSetSpec mirrors the MCPGPluginSet admission rules.
func ValidatePluginSetSpec(spec map[string]any) []Finding {
	var f []Finding
	entries := asSlice(spec["entries"])
	if len(entries) == 0 {
		f = append(f, Finding{"pluginSet.entries.nonEmpty", "entries must be non-empty"})
	}
	ids := map[string]bool{}
	for i, e := range entries {
		em := asMap(e)
		id := asString(em["id"])
		if blank(id) {
			f = append(f, Finding{"pluginSet.entries.id.nonEmpty", "spec.entries[" + itoa(i) + "].id must not be empty"})
		} else if !strings.Contains(id, ".") {
			f = append(f, Finding{"pluginSet.entries.id.reverseDns", "spec.entries[" + itoa(i) + "].id is not reverse-DNS form"})
		}
		if blank(asString(asMap(em["pluginRef"])["name"])) {
			f = append(f, Finding{"pluginSet.entries.pluginRef.name", "spec.entries[" + itoa(i) + "].pluginRef.name must not be empty"})
		}
		if id != "" {
			ids[id] = true
		}
	}
	dups := findDuplicates(entries, func(e any) string { return asString(asMap(e)["id"]) })
	if len(dups) > 0 {
		f = append(f, Finding{"pluginSet.entries.uniqueId", "duplicate entry ids: " + strings.Join(dups, ",")})
	}
	// capabilityGrants is a MAP (id → [capabilities]); keys must name an entry
	// id and each grant list must be non-empty (plugin_set.rs:85-100).
	for id, v := range asMap(spec["capabilityGrants"]) {
		if !ids[id] {
			f = append(f, Finding{"pluginSet.capabilityGrants.unknownId", "capabilityGrants['" + id + "'] names an id not in entries"})
		} else if len(asSlice(v)) == 0 {
			f = append(f, Finding{"pluginSet.capabilityGrants.empty", "capabilityGrants['" + id + "'] must not be empty"})
		}
	}
	return f
}

// ValidateRevocationListSpec mirrors the MCPGRevocationList admission rules.
func ValidateRevocationListSpec(spec map[string]any) []Finding {
	var f []Finding
	// JSON numbers decode to float64.
	if v, ok := spec["version"].(float64); !ok || v != 1 {
		f = append(f, Finding{"revocationList.version", "version must be 1"})
	}
	revs := asSlice(spec["revocations"])
	for _, r := range revs {
		rm := asMap(r)
		if !IsSha256Hex(asString(rm["artifactSha256"])) {
			f = append(f, Finding{"revocationList.sha256", "artifactSha256 must be 64 hex chars"})
		}
		// empty reason defeats the audit trail (revocation_list.rs:86).
		if blank(asString(rm["reason"])) {
			f = append(f, Finding{"revocationList.reason", "revocation reason must not be empty"})
		}
	}
	// dedup is case-insensitive in the operator (hashes lowercased) — ABCD…
	// and abcd… collide (trust-6).
	dups := findDuplicates(revs, func(r any) string {
		return strings.ToLower(asString(asMap(r)["artifactSha256"]))
	})
	if len(dups) > 0 {
		f = append(f, Finding{"revocationList.noDuplicates", "duplicate hashes: " + strings.Join(dups, ",")})
	}
	return f
}

// ValidateClusterSpec mirrors the MCPGCluster admission rules
// (k8s/operator/src/admission/validators/cluster.rs).
func ValidateClusterSpec(spec map[string]any) []Finding {
	var f []Finding
	// backend is a snake_case string; default (absent) is single_node.
	backend := asString(spec["backend"])
	singleNode := backend == "" || backend == "single_node"
	configEmpty := len(asMap(spec["config"])) == 0
	if singleNode && !configEmpty {
		f = append(f, Finding{"cluster.singleNode.noConfig", "spec.config must be empty for the single_node backend (it takes no parameters)"})
	}
	if !singleNode && configEmpty {
		f = append(f, Finding{"cluster.backend.configRequired", "spec.config must not be empty for an external backend — it needs at least a connection address"})
	}
	// Transport security (W-9): reject a plaintext coordinator unless opted out
	// with spec.config.allow_insecure_transport: true. Mirrors the gateway boot
	// guard + the operator admission webhook.
	cfg := asMap(spec["config"])
	optedOut, _ := cfg["allow_insecure_transport"].(bool)
	if !singleNode && !configEmpty && !optedOut {
		lead := func(v any) string { return strings.TrimLeft(asString(v), " \t") }
		insecure := ""
		switch backend {
		case "redis":
			if strings.HasPrefix(lead(cfg["url"]), "redis://") {
				insecure = "the redis `url` uses the plaintext `redis://` scheme (use `rediss://`)"
			}
		case "consul":
			if strings.HasPrefix(lead(cfg["address"]), "http://") {
				insecure = "the consul `address` uses the plaintext `http://` scheme (use `https://`)"
			}
		case "etcd":
			for _, e := range asSlice(cfg["endpoints"]) {
				if !strings.HasPrefix(lead(e), "https://") {
					insecure = "an etcd `endpoint` is not an `https://` URL (use `https://`)"
					break
				}
			}
		case "nats":
			if rt, ok := asMap(cfg["tls"])["require_tls"].(bool); ok && !rt {
				insecure = "nats `tls.require_tls` is set to `false` (plaintext)"
			}
		}
		if insecure != "" {
			f = append(f, Finding{"cluster.transport.insecure", "spec.config: " + insecure + ". Set spec.config.allow_insecure_transport: true to accept plaintext (local/dev only)."})
		}
	}
	seen := map[string]bool{}
	for i, c := range asSlice(spec["credentialRefs"]) {
		cm := asMap(c)
		if blank(asString(cm["name"])) {
			f = append(f, Finding{"cluster.credentialRefs.name", "spec.credentialRefs[" + itoa(i) + "].name must not be empty"})
			continue
		}
		if blank(asString(cm["secretName"])) {
			f = append(f, Finding{"cluster.credentialRefs.secretName", "spec.credentialRefs[" + itoa(i) + "].secretName must not be empty"})
		}
		name := asString(cm["name"])
		if seen[name] {
			f = append(f, Finding{"cluster.credentialRefs.uniqueName", "spec.credentialRefs name '" + name + "' is duplicated"})
		}
		seen[name] = true
	}
	return f
}

// ValidateRouteSpec mirrors the MCPGRoute admission rules
// (k8s/operator/src/admission/validators/route.rs). The tenant-unset case is an
// admit-with-warning in the webhook, so it is NOT a reject here.
func ValidateRouteSpec(spec map[string]any) []Finding {
	var f []Finding
	if blank(asString(asMap(spec["gatewayRef"])["name"])) {
		f = append(f, Finding{"route.gatewayRef.name", "spec.gatewayRef.name must not be empty"})
	}
	tools := asSlice(asMap(spec["match"])["tools"])
	if len(tools) == 0 {
		f = append(f, Finding{"route.match.tools.nonEmpty", "spec.match.tools must list at least one tool"})
	}
	seen := map[string]bool{}
	for i, t := range tools {
		id := strings.TrimSpace(asString(asMap(t)["id"]))
		if id == "" {
			f = append(f, Finding{"route.match.tools.id", "spec.match.tools[" + itoa(i) + "].id must not be empty"})
			continue
		}
		if seen[id] {
			f = append(f, Finding{"route.match.tools.uniqueId", "spec.match.tools contains duplicate tool id '" + id + "'"})
		}
		seen[id] = true
	}
	for _, chain := range []string{"identityChain", "policyChain", "auditChain"} {
		for i, id := range asSlice(spec[chain]) {
			if blank(asString(id)) {
				f = append(f, Finding{"route.chain.nonEmptyId", "spec." + chain + "[" + itoa(i) + "] must not be empty"})
			}
		}
	}
	return f
}

// ValidateTenantSpec mirrors the MCPGTenant admission rules
// (k8s/operator/src/admission/validators/tenant.rs).
func ValidateTenantSpec(spec map[string]any) []Finding {
	var f []Finding
	namespaces := asSlice(spec["namespaces"])
	if len(namespaces) == 0 {
		f = append(f, Finding{"tenant.namespaces.nonEmpty", "spec.namespaces must not be empty"})
	}
	seen := map[string]bool{}
	for _, ns := range namespaces {
		s := asString(ns)
		if blank(s) {
			f = append(f, Finding{"tenant.namespaces.nonEmptyEntry", "spec.namespaces[] entries must not be empty"})
			continue
		}
		if seen[s] {
			f = append(f, Finding{"tenant.namespaces.unique", "spec.namespaces lists '" + s + "' more than once"})
		}
		seen[s] = true
	}
	for i, a := range asSlice(spec["allowedPlugins"]) {
		am := asMap(a)
		nameSet := !blank(asString(am["name"]))
		prefixSet := !blank(asString(am["registryPrefix"]))
		if !nameSet && !prefixSet {
			f = append(f, Finding{"tenant.allowedPlugins.matcher", "spec.allowedPlugins[" + itoa(i) + "] must set name or registryPrefix"})
		}
	}
	if q := asMap(spec["quotas"]); q != nil {
		for _, field := range []string{"maxGateways", "maxPluginSets", "maxRoutes", "maxReplicasPerGateway"} {
			if v, ok := asFloat(q[field]); ok && v < 0 {
				f = append(f, Finding{"tenant.quotas.nonNegative", "spec.quotas." + field + " must be ≥ 0"})
			}
		}
	}
	if ia := asMap(spec["identityAttribute"]); ia != nil && blank(asString(ia["key"])) {
		f = append(f, Finding{"tenant.identityAttribute.key", "spec.identityAttribute.key must not be empty when set"})
	}
	return f
}

// ValidatePluginMirrorSpec mirrors the MCPGPluginMirror admission rules
// (k8s/operator/src/admission/validators/plugin_mirror.rs).
func ValidatePluginMirrorSpec(spec map[string]any) []Finding {
	var f []Finding
	svc := asMap(asMap(spec["endpoint"])["service"])
	if blank(asString(svc["namespace"])) {
		f = append(f, Finding{"pluginMirror.endpoint.service.namespace", "spec.endpoint.service.namespace must not be empty"})
	}
	if blank(asString(svc["name"])) {
		f = append(f, Finding{"pluginMirror.endpoint.service.name", "spec.endpoint.service.name must not be empty"})
	}
	if port, _ := asFloat(svc["port"]); port == 0 {
		f = append(f, Finding{"pluginMirror.endpoint.service.port", "spec.endpoint.service.port must be in 1..=65535"})
	}
	up := asMap(spec["upstream"])
	registry := asString(up["registry"])
	if blank(registry) {
		f = append(f, Finding{"pluginMirror.upstream.registry", "spec.upstream.registry must not be empty"})
	} else if !strings.Contains(registry, ".") && !strings.Contains(registry, ":") {
		f = append(f, Finding{"pluginMirror.upstream.registryHost", "spec.upstream.registry '" + registry + "' does not look like a registry host"})
	}
	if blank(asString(up["namespace"])) {
		f = append(f, Finding{"pluginMirror.upstream.namespace", "spec.upstream.namespace must not be empty"})
	}
	if auth := asMap(spec["auth"]); auth != nil {
		if blank(asString(asMap(auth["secretRef"])["secretName"])) {
			f = append(f, Finding{"pluginMirror.auth.secretName", "spec.auth.secretRef.secretName must not be empty when auth is set"})
		}
	}
	return f
}

// ValidateByType dispatches by Pulumi/K8s resource type token (…:MCPGGateway).
func ValidateByType(typ string, spec map[string]any) []Finding {
	switch {
	case strings.HasSuffix(typ, ":MCPGGateway"):
		return ValidateGatewaySpec(spec)
	case strings.HasSuffix(typ, ":MCPGPlugin"):
		return ValidatePluginSpec(spec)
	case strings.HasSuffix(typ, ":MCPGPluginSet"):
		return ValidatePluginSetSpec(spec)
	case strings.HasSuffix(typ, ":MCPGRevocationList"):
		return ValidateRevocationListSpec(spec)
	case strings.HasSuffix(typ, ":MCPGCluster"):
		return ValidateClusterSpec(spec)
	case strings.HasSuffix(typ, ":MCPGRoute"):
		return ValidateRouteSpec(spec)
	case strings.HasSuffix(typ, ":MCPGTenant"):
		return ValidateTenantSpec(spec)
	case strings.HasSuffix(typ, ":MCPGPluginMirror"):
		return ValidatePluginMirrorSpec(spec)
	}
	return nil
}
