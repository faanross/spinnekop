// cmd/build/main.go is used to compile a binary that is used to build spinnekop agent
// this 2-step process is used since we wish to statically-compile YAML config and
// run ValidateRequest() on field values at compile-time

package main

import (
	"flag"
	"fmt"
	"github.com/faanross/spinnekop/internal/models"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// NOTE: If no flag is provided will compile for host OS + ARCH
	target := flag.String("target", "current", "Build target: current, windows-amd64, linux-amd64, darwin-amd64, darwin-arm64, all")
	flag.Parse()

	// Generate  config.go file from yamlConfigSourcePath
	if err := generateEmbeddedConfig(); err != nil {
		log.Fatalf("Build Error: Failed to generate embedded config: %v", err)
	}

	// Compile agent based on the target flag (or default host OS)
	var buildErrors []string

	buildSpecificTarget := func(os, arch string) {
		if err := buildAgent(os, arch, defaultOutputDir, defaultBinaryNameBase); err != nil {
			errStr := fmt.Sprintf("Error building for %s/%s: %v", os, arch, err)
			log.Println(errStr)
			buildErrors = append(buildErrors, errStr)
		}
	}

	switch *target {
	case "current":
		log.Println("Build target: current host OS/ARCH")
		// Get host OS/Arch
		cmdHost := exec.Command("go", "env", "GOOS")
		goosBytes, _ := cmdHost.Output()
		hostOS := strings.TrimSpace(string(goosBytes))
		if hostOS == "" {
			hostOS = "darwin"
		} // fallback in case OS cannot be determined

		cmdHostArch := exec.Command("go", "env", "GOARCH")
		goarchBytes, _ := cmdHostArch.Output()
		hostArch := strings.TrimSpace(string(goarchBytes))
		if hostArch == "" {
			hostArch = "amd64"
		} // fallback in case ARCH cannot be determined
		buildSpecificTarget(hostOS, hostArch)
	case "windows-amd64":
		buildSpecificTarget("windows", "amd64")
	case "linux-amd64":
		buildSpecificTarget("linux", "amd64")
	case "darwin-amd64":
		buildSpecificTarget("darwin", "amd64")
	case "darwin-arm64":
		buildSpecificTarget("darwin", "arm64")
	case "all":
		log.Println("Build target: all common platforms")
		buildSpecificTarget("windows", "amd64")
		buildSpecificTarget("linux", "amd64")
		buildSpecificTarget("darwin", "amd64")
		buildSpecificTarget("darwin", "arm64")
	default:
		log.Fatalf("Build Error: Unknown target '%s'. Valid targets: current, windows-amd64, linux-amd64, darwin-amd64, darwin-arm64, all", *target)
	}

	if len(buildErrors) > 0 {
		log.Printf("Build process finished with %d error(s):", len(buildErrors))
		for _, e := range buildErrors {
			log.Println(e)
		}
		os.Exit(1)
	} else {
		log.Println("Build process finished successfully.")
	}

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

	// Write template to config.go
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

// buildAgent compiles the agent for the specified target OS and architecture.
func buildAgent(targetOS, targetArch, outputDir, binaryNameBase string) error {
	// create agent binary name
	finalBinaryName := fmt.Sprintf("%s_%s_%s", binaryNameBase, targetOS, targetArch)
	if targetOS == "windows" {
		finalBinaryName += ".exe"
	}
	outputPath := filepath.Join(outputDir, finalBinaryName)

	log.Printf("Build: Compiling agent for %s/%s -> %s", targetOS, targetArch, outputPath)

	// create command based on go build
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outputPath, agentMainPackagePath)
	cmd.Env = append(os.Environ(), // Inherit current environment
		fmt.Sprintf("GOOS=%s", targetOS),
		fmt.Sprintf("GOARCH=%s", targetArch),
		"CGO_ENABLED=0", // Disable CGO for easier cross-compilation
	)

	// here we actually compile the agent
	buildOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed for %s/%s: %w\nBuild Output:\n%s", targetOS, targetArch, err, string(buildOutput))
	}
	log.Printf("Build: Successfully built agent: %s", outputPath)
	return nil
}
