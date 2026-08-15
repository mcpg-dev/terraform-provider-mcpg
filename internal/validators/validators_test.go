package validators

import (
	"strings"
	"testing"
)

func hasRule(f []Finding, rule string) bool {
	for _, x := range f {
		if x.Rule == rule {
			return true
		}
	}
	return false
}

func TestGatewayWorkloadIdentityOneOf(t *testing.T) {
	f := ValidateGatewaySpec(map[string]any{
		"image":            map[string]any{},
		"workloadIdentity": map[string]any{"aws": map[string]any{}, "gcp": map[string]any{}},
	})
	if !hasRule(f, "gateway.workloadIdentity.oneOf") {
		t.Fatalf("expected oneOf finding, got %v", f)
	}
}

func TestGatewayMinimalAccepted(t *testing.T) {
	if f := ValidateGatewaySpec(map[string]any{"image": map[string]any{"repository": "x"}}); len(f) != 0 {
		t.Fatalf("expected accept, got %v", f)
	}
}

func TestPluginTagOnlyRejected(t *testing.T) {
	f := ValidatePluginSpec(map[string]any{"oci": map[string]any{"image": "ghcr.io/x:1.0"}, "trust": map[string]any{}})
	if !hasRule(f, "plugin.trust.anchor") {
		t.Fatalf("expected anchor finding, got %v", f)
	}
}

func TestPluginCosignUnanchored(t *testing.T) {
	f := ValidatePluginSpec(map[string]any{
		"oci":   map[string]any{"image": "ghcr.io/x:1.0"},
		"trust": map[string]any{"cosignIdentity": map[string]any{"certificateIdentityRegexp": "https://github.com/.+", "oidcIssuer": "x"}},
	})
	if !hasRule(f, "plugin.cosign.anchoredRegexp") {
		t.Fatalf("expected anchoredRegexp finding, got %v", f)
	}
}

func TestPluginDigestAccepted(t *testing.T) {
	img := "ghcr.io/x@sha256:" + strings.Repeat("a", 64)
	// A fully-formed plugin: identity + class + version + digest pin + the
	// mandatory signingKeyRef → accept.
	spec := map[string]any{
		"pluginId":    "dev.mcpg.backend.sql",
		"pluginClass": "backend",
		"version":     "1.4.2",
		"oci":         map[string]any{"image": img},
		"trust":       map[string]any{"signingKeyRef": map[string]any{"secretName": "k"}},
	}
	if f := ValidatePluginSpec(spec); len(f) != 0 {
		t.Fatalf("expected accept, got %v", f)
	}
}

func TestPluginBadClassAndIdRejected(t *testing.T) {
	img := "ghcr.io/x@sha256:" + strings.Repeat("a", 64)
	f := ValidatePluginSpec(map[string]any{
		"pluginId":    "noDotId",
		"pluginClass": "frobnicator",
		"version":     "1.0",
		"oci":         map[string]any{"image": img},
		"trust":       map[string]any{"signingKeyRef": map[string]any{"secretName": "k"}},
	})
	if !hasRule(f, "plugin.pluginId.reverseDns") || !hasRule(f, "plugin.pluginClass.known") {
		t.Fatalf("expected pluginId + pluginClass findings, got %v", f)
	}
}

func TestPluginMissingSigningKeyRejected(t *testing.T) {
	img := "ghcr.io/x@sha256:" + strings.Repeat("a", 64)
	// digest-pinned but no signingKeyRef → reject (trust-9).
	f := ValidatePluginSpec(map[string]any{"oci": map[string]any{"image": img}, "trust": map[string]any{}})
	found := false
	for _, x := range f {
		if x.Rule == "plugin.trust.signingKeyRef.required" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected plugin.trust.signingKeyRef.required, got %v", f)
	}
}

func TestRevocationBadShaAndDuplicates(t *testing.T) {
	a := strings.Repeat("a", 64)
	f := ValidateRevocationListSpec(map[string]any{
		"version":     float64(1),
		"revocations": []any{map[string]any{"artifactSha256": "xyz"}, map[string]any{"artifactSha256": a}, map[string]any{"artifactSha256": a}},
	})
	if !hasRule(f, "revocationList.sha256") || !hasRule(f, "revocationList.noDuplicates") {
		t.Fatalf("expected sha + dup findings, got %v", f)
	}
}

func TestHelpers(t *testing.T) {
	// case-insensitive 64-hex (the operator accepts uppercase — adm-2/trust-5).
	if !IsSha256Hex(strings.Repeat("a", 64)) || !IsSha256Hex(strings.Repeat("A", 64)) {
		t.Fatal("sha hex check should accept lower + upper case")
	}
	if IsSha256Hex(strings.Repeat("a", 63)) || IsSha256Hex(strings.Repeat("g", 64)) {
		t.Fatal("sha hex check should reject wrong length / non-hex")
	}
	if !IsAnchoredRegexp("^x$") || IsAnchoredRegexp("x") {
		t.Fatal("anchored regexp check wrong")
	}
	// RE2 (and the operator) reject lookahead — the Pulumi side mirrors this.
	if IsAnchoredRegexp("^(?=.*x).*$") {
		t.Fatal("RE2-incompatible lookahead should be rejected")
	}
}

func TestDispatch(t *testing.T) {
	if len(ValidateByType("k8s:mcpg.dev/v1alpha1:MCPGGateway", map[string]any{})) == 0 {
		t.Fatal("expected gateway findings (missing image)")
	}
	if len(ValidateByType("k8s:core/v1:ConfigMap", map[string]any{})) != 0 {
		t.Fatal("expected non-MCPG type to be ignored")
	}
}
