// contract-check is the Terraform-provider side of the shared admission
// contract test. It takes a resource type token + a spec JSON and prints the
// JSON array of violated rule ids — so iac/contract/run.sh can assert the
// provider's validators agree with the Pulumi/CrossGuard validators and the
// real admission webhook on every fixture.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mcpg-dev/terraform-provider-mcpg/internal/validators"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: contract-check <typeToken> <specJSON>")
		os.Exit(2)
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(os.Args[2]), &spec); err != nil {
		fmt.Fprintln(os.Stderr, "bad spec json:", err)
		os.Exit(2)
	}
	rules := []string{}
	for _, f := range validators.ValidateByType(os.Args[1], spec) {
		rules = append(rules, f.Rule)
	}
	out, _ := json.Marshal(rules)
	fmt.Println(string(out))
}
