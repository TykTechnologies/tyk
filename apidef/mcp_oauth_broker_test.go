package apidef

import "testing"

func TestMCPOAuthBrokerConfigValidate(t *testing.T) {
	valid := MCPOAuthBrokerConfig{
		Enabled: true, PublicOrigin: "https://gateway.example",
		PublicResource: "https://gateway.example/mcp/", UpstreamResource: "https://upstream.example/mcp/",
	}
	if err := valid.Validate("/mcp/"); err != nil {
		t.Fatalf("valid broker config: %v", err)
	}

	loopback := MCPOAuthBrokerConfig{
		Enabled: true, PublicOrigin: "http://127.0.0.1:8080",
		PublicResource: "http://127.0.0.1:8080/", UpstreamResource: "http://localhost:9090/mcp",
		AllowInsecureLoopback: true,
	}
	if err := loopback.Validate("/"); err != nil {
		t.Fatalf("loopback development config: %v", err)
	}

	for name, mutate := range map[string]func(*MCPOAuthBrokerConfig){
		"host-derived resource": func(config *MCPOAuthBrokerConfig) { config.PublicResource = "https://attacker.example/mcp/" },
		"origin path":           func(config *MCPOAuthBrokerConfig) { config.PublicOrigin += "/base" },
		"origin query":          func(config *MCPOAuthBrokerConfig) { config.PublicOrigin += "?x=1" },
		"origin credentials":    func(config *MCPOAuthBrokerConfig) { config.PublicOrigin = "https://user@gateway.example" },
		"noncanonical origin":   func(config *MCPOAuthBrokerConfig) { config.PublicOrigin = "HTTPS://GATEWAY.EXAMPLE:443" },
		"insecure public": func(config *MCPOAuthBrokerConfig) {
			config.PublicOrigin = "http://gateway.example"
			config.PublicResource = "http://gateway.example/mcp/"
		},
		"insecure upstream": func(config *MCPOAuthBrokerConfig) { config.UpstreamResource = "http://upstream.example/mcp/" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.Validate("/mcp/"); err == nil {
				t.Fatal("invalid broker configuration accepted")
			}
		})
	}
}
