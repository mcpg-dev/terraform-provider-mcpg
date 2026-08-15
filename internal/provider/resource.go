package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/mcpg-dev/terraform-provider-mcpg/internal/validators"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const fieldManager = "terraform-provider-mcpg"

func gvr(res string) k8sschema.GroupVersionResource {
	return k8sschema.GroupVersionResource{Group: "mcpg.dev", Version: "v1alpha1", Resource: res}
}

// crResource is a generic MCPG custom-resource. `spec` is the CR spec as JSON
// (use jsonencode), validated at plan time against the operator's admission
// rules. Fully-typed per-kind schemas are a codegen follow-up; this
// generic shape already delivers the provider's distinctive value: plan-time
// validation + CRUD + drift over the typed kind.
type crResource struct {
	typeSuffix string // e.g. "gateway" -> mcpg_gateway
	kind       string // e.g. "MCPGGateway"
	gvr        k8sschema.GroupVersionResource
	namespaced bool
	validate   func(map[string]any) []validators.Finding
	data       *providerData
}

func newCRResource(suffix, kind, res string, namespaced bool, validate func(map[string]any) []validators.Finding) func() resource.Resource {
	return func() resource.Resource {
		return &crResource{typeSuffix: suffix, kind: kind, gvr: gvr(res), namespaced: namespaced, validate: validate}
	}
}

type crModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Namespace  types.String `tfsdk:"namespace"`
	Spec       types.String `tfsdk:"spec"`
	ConfigHash types.String `tfsdk:"config_hash"`
}

func (r *crResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.typeSuffix
}

func (r *crResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nsDesc := "Namespace."
	if !r.namespaced {
		nsDesc = "Ignored — " + r.kind + " is cluster-scoped."
	}
	resp.Schema = rschema.Schema{
		MarkdownDescription: "A " + r.kind + ". `spec` is the CR spec as JSON (use `jsonencode`); " +
			"validated at plan time against the operator's admission rules.",
		Attributes: map[string]rschema.Attribute{
			"id":          rschema.StringAttribute{Computed: true, MarkdownDescription: "Resource identity."},
			"name":        rschema.StringAttribute{Required: true},
			"namespace":   rschema.StringAttribute{Optional: true, MarkdownDescription: nsDesc},
			"spec":        rschema.StringAttribute{Required: true, MarkdownDescription: "CR spec as JSON (`jsonencode`)."},
			"config_hash": rschema.StringAttribute{Computed: true, MarkdownDescription: "status.configHash (drift signal), when present."},
		},
	}
}

func (r *crResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.data = data
}

// ValidateConfig mirrors the operator's admission webhook at plan time, so the
// same inputs admission would reject fail `terraform plan` locally.
func (r *crResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m crModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.namespaced && (m.Namespace.IsNull() || m.Namespace.ValueString() == "") {
		resp.Diagnostics.AddAttributeError(path.Root("namespace"), "namespace is required", r.kind+" is namespaced")
	}
	if m.Spec.IsNull() || m.Spec.IsUnknown() {
		return
	}
	findings, err := validateSpec(r.validate, m.Spec.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("spec"), "Invalid spec JSON", err.Error())
		return
	}
	for _, f := range findings {
		resp.Diagnostics.AddAttributeError(path.Root("spec"), f.Rule, f.Message)
	}
}

// validateSpec is the testable core of ValidateConfig.
func validateSpec(validate func(map[string]any) []validators.Finding, specJSON string) ([]validators.Finding, error) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return nil, err
	}
	return validate(spec), nil
}

func (r *crResource) build(m crModel) (*unstructured.Unstructured, error) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(m.Spec.ValueString()), &spec); err != nil {
		return nil, fmt.Errorf("spec is not valid JSON: %w", err)
	}
	meta := map[string]any{"name": m.Name.ValueString()}
	if r.namespaced {
		meta["namespace"] = m.Namespace.ValueString()
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "mcpg.dev/v1alpha1",
		"kind":       r.kind,
		"metadata":   meta,
		"spec":       spec,
	}}, nil
}

func (r *crResource) ri(ns string) dynamic.ResourceInterface {
	if r.namespaced {
		return r.data.dyn.Resource(r.gvr).Namespace(ns)
	}
	return r.data.dyn.Resource(r.gvr)
}

func (r *crResource) applyComputed(m *crModel, obj *unstructured.Unstructured) {
	id := m.Name.ValueString()
	if r.namespaced {
		id = m.Namespace.ValueString() + "/" + id
	}
	m.ID = types.StringValue(id)
	hash, _, _ := unstructured.NestedString(obj.Object, "status", "configHash")
	m.ConfigHash = types.StringValue(hash)
}

func (r *crResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m crModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj, err := r.build(m)
	if err != nil {
		resp.Diagnostics.AddError("Invalid spec", err.Error())
		return
	}
	created, err := r.ri(m.Namespace.ValueString()).Create(ctx, obj, metav1.CreateOptions{FieldManager: fieldManager})
	if err != nil {
		resp.Diagnostics.AddError("Create "+r.kind+" failed", err.Error())
		return
	}
	r.applyComputed(&m, created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *crResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m crModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.ri(m.Namespace.ValueString()).Get(ctx, m.Name.ValueString(), metav1.GetOptions{})
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}
	r.applyComputed(&m, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *crResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m crModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj, err := r.build(m)
	if err != nil {
		resp.Diagnostics.AddError("Invalid spec", err.Error())
		return
	}
	updated, err := r.ri(m.Namespace.ValueString()).Apply(ctx, m.Name.ValueString(), obj, metav1.ApplyOptions{FieldManager: fieldManager, Force: true})
	if err != nil {
		resp.Diagnostics.AddError("Update "+r.kind+" failed", err.Error())
		return
	}
	r.applyComputed(&m, updated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *crResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m crModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.ri(m.Namespace.ValueString()).Delete(ctx, m.Name.ValueString(), metav1.DeleteOptions{}); err != nil {
		resp.Diagnostics.AddError("Delete "+r.kind+" failed", err.Error())
	}
}
