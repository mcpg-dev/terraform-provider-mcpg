package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/mcpg-dev/terraform-provider-mcpg/internal/validators"
)

func hasRule(f []validators.Finding, rule string) bool {
	for _, x := range f {
		if x.Rule == rule {
			return true
		}
	}
	return false
}

func TestValidateSpec_GatewayTwoWorkloadIdentities(t *testing.T) {
	f, err := validateSpec(validators.ValidateGatewaySpec, `{"image":{},"workloadIdentity":{"aws":{},"gcp":{}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(f, "gateway.workloadIdentity.oneOf") {
		t.Fatalf("expected oneOf finding, got %v", f)
	}
}

func TestValidateSpec_PluginDigestAccepted(t *testing.T) {
	spec := `{"pluginId":"dev.mcpg.backend.sql","pluginClass":"backend","version":"1.0","oci":{"image":"ghcr.io/x@sha256:` + strings.Repeat("a", 64) + `"},"trust":{"signingKeyRef":{"secretName":"k"}}}`
	f, err := validateSpec(validators.ValidatePluginSpec, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("expected accept, got %v", f)
	}
}

func TestValidateSpec_BadJSON(t *testing.T) {
	if _, err := validateSpec(validators.ValidateGatewaySpec, `{nope`); err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestBuild_NamespacedAndCluster(t *testing.T) {
	ns := &crResource{kind: "MCPGGateway", namespaced: true}
	obj, err := ns.build(crModel{
		Name: types.StringValue("g"), Namespace: types.StringValue("mcpg-system"),
		Spec: types.StringValue(`{"image":{"repository":"x"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	meta := obj.Object["metadata"].(map[string]any)
	if obj.Object["kind"] != "MCPGGateway" || meta["namespace"] != "mcpg-system" {
		t.Fatalf("namespaced build wrong: %v", obj.Object)
	}

	cl := &crResource{kind: "MCPGPlugin", namespaced: false}
	obj2, err := cl.build(crModel{Name: types.StringValue("p"), Spec: types.StringValue(`{"oci":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	meta2 := obj2.Object["metadata"].(map[string]any)
	if _, ok := meta2["namespace"]; ok {
		t.Fatalf("cluster-scoped resource must not set namespace: %v", meta2)
	}
}
