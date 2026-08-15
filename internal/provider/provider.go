// Package provider implements the native terraform-provider-mcpg over the
// operator/CRD plane (the K8s API). Its distinctive value over the module suite
// is plan-time validation that mirrors the operator's admission webhook
// — see resource.go's ValidateConfig.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/mcpg-dev/terraform-provider-mcpg/internal/validators"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

type mcpgProvider struct {
	version string
}

type mcpgProviderModel struct {
	Kubeconfig types.String `tfsdk:"kubeconfig"`
	Context    types.String `tfsdk:"context"`
}

// providerData is handed to each resource's Configure.
type providerData struct {
	dyn dynamic.Interface
}

// New returns the provider factory used by main and the acceptance tests.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &mcpgProvider{version: version} }
}

func (p *mcpgProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "mcpg"
	resp.Version = p.version
}

func (p *mcpgProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage MCPG (`mcpg.dev`) custom resources via the operator plane. " +
			"Auth mirrors the standard kubeconfig chain.",
		Attributes: map[string]schema.Attribute{
			"kubeconfig": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to a kubeconfig file. Falls back to KUBECONFIG / in-cluster config.",
			},
			"context": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "kubeconfig context to use.",
			},
		},
	}
}

func (p *mcpgProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg mcpgProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if !cfg.Kubeconfig.IsNull() && cfg.Kubeconfig.ValueString() != "" {
		loadingRules.ExplicitPath = cfg.Kubeconfig.ValueString()
	}
	overrides := &clientcmd.ConfigOverrides{}
	if !cfg.Context.IsNull() && cfg.Context.ValueString() != "" {
		overrides.CurrentContext = cfg.Context.ValueString()
	}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err != nil {
		resp.Diagnostics.AddError("Unable to load kubeconfig", err.Error())
		return
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		resp.Diagnostics.AddError("Unable to build Kubernetes client", err.Error())
		return
	}

	data := &providerData{dyn: dyn}
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *mcpgProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newCRResource("gateway", "MCPGGateway", "mcpggateways", true, validators.ValidateGatewaySpec),
		newCRResource("plugin", "MCPGPlugin", "mcpgplugins", false, validators.ValidatePluginSpec),
		newCRResource("plugin_set", "MCPGPluginSet", "mcpgpluginsets", true, validators.ValidatePluginSetSpec),
		newCRResource("revocation_list", "MCPGRevocationList", "mcpgrevocationlists", false, validators.ValidateRevocationListSpec),
		// Coverage parity with the operator's 8 CRDs (beta-gap crd-cov-2).
		newCRResource("cluster", "MCPGCluster", "mcpgclusters", false, validators.ValidateClusterSpec),
		newCRResource("route", "MCPGRoute", "mcpgroutes", true, validators.ValidateRouteSpec),
		newCRResource("tenant", "MCPGTenant", "mcpgtenants", false, validators.ValidateTenantSpec),
		newCRResource("plugin_mirror", "MCPGPluginMirror", "mcpgpluginmirrors", false, validators.ValidatePluginMirrorSpec),
	}
}

func (p *mcpgProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
