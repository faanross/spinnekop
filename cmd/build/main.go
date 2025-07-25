// cmd/build/main.go is used to compile a binary that is used to build spinnekop agent
// this 2-step process is used since we wish to statically-compile YAML config and
// run ValidateRequest() on field values at compile-time

package main

import (
	"fmt"
	"github.com/faanross/spinnekop/internal/models"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
	"text/template"
)

const (
	// Paths relative to the project root
	yamlConfigSourcePath   = "./configs/response.yaml" // Agent's YAML config
	embeddedGoConfigTarget = "./cmd/agent/config.go"   // Output path for generated Go config
	agentMainPackagePath   = "./cmd/agent"             // Path to agent's main package for compilation
	defaultOutputDir       = "./bin"                   // Default output directory for binaries
	defaultBinaryNameBase  = "spinnekop_Agent"         // Naming convention for compiled agent
)

func main() {
	log.Println("🕷️🕷️🕷️ Starting Spinnekop Agent Build process 🕷️🕷️🕷️")

}

// generateEmbeddedConfig reads the YAML then writes the cmd/agent/config.go file for static compilation
func generateEmbeddedConfig() error {

	// Read YAML file from disk - as specified in yamlConfigSourcePath
	log.Printf("Build: Reading YAML config from '%s'", yamlConfigSourcePath)
	yamlFile, err := os.ReadFile(yamlConfigSourcePath)
	if err != nil {
		return fmt.Errorf("failed to read YAML config file '%s': %w", yamlConfigSourcePath, err)
	}

	// Instantiate DNSRequest struct and unmarshall YAML contents into it
	var cfgFromYAML models.DNSRequest
	err = yaml.Unmarshal(yamlFile, &cfgFromYAML)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML from '%s': %w", yamlConfigSourcePath, err)
	}

	// Create new template based on configGoTemplate we defined at the top
	tmpl, err := template.New("config").Parse(configGoTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse Go config template: %w", err)
	}

	// Create config.go in cmd/agent
	file, err := os.Create(embeddedGoConfigTarget)
	if err != nil {
		return fmt.Errorf("failed to create Go config file '%s': %w", embeddedGoConfigTarget, err)
	}
	defer file.Close()

	// Execute applies the parsed template to the specified data object, and writes the output to file.
	// In other words, here we write our template to the file
	if err := tmpl.Execute(file, cfgFromYAML); err != nil {
		return fmt.Errorf("failed to execute Go config template into '%s': %w", embeddedGoConfigTarget, err)
	}
	log.Printf("Build: Successfully wrote embedded configuration to '%s'", embeddedGoConfigTarget)

	// Manually tidy generated file up using gofmt
	cmdFmt := exec.Command("gofmt", "-w", embeddedGoConfigTarget)
	if output, errFmt := cmdFmt.CombinedOutput(); errFmt != nil {
		// Log as a warning, non-fatal for the build process itself
		log.Printf("Build Warning: gofmt failed on '%s': %v\nOutput: %s", embeddedGoConfigTarget, errFmt, string(output))
	} else {
		log.Printf("Build: Ran gofmt on '%s'", embeddedGoConfigTarget)
	}

	return nil
}
