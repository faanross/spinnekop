// cmd/build/main.go is used to compile a binary that is used to build spinnekop agent
// this 2-step process is used since we wish to statically-compile YAML config and
// run ValidateRequest() on field values at compile-time

package main

const (
	// Paths relative to the project root
	yamlConfigSourcePath   = "./configs/request.yaml" // Agent's YAML config
	embeddedGoConfigTarget = "./cmd/agent/config.go"  // Output path for generated Go config
	agentMainPackagePath   = "./cmd/agent"            // Path to agent's main package for compilation
	defaultOutputDir       = "./bin"                  // Default output directory for binaries
	defaultBinaryNameBase  = "spinnekop_Agent"        // Naming convention for compiled agent
)
