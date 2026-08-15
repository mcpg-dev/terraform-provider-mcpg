package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/mcpg-dev/terraform-provider-mcpg/internal/provider"
)

// version is overwritten at release time (-ldflags).
var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/mcpg-dev/mcpg",
	})
	if err != nil {
		log.Fatal(err)
	}
}
