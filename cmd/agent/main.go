package main

import (
	"fmt"
	"os"
)

// assume go run from root, otherwise change path
var pathToYamlFile = "./configs/agent.yaml"

func main() {

	// read yaml-file from disk

	yamlFile, err := os.ReadFile(pathToYamlFile)
	if err != nil {
		fmt.Printf("Error reading YAML file: %v\n", err)
		return
	}

}
