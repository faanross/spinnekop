package main

import "github.com/faanross/spinnekop/internal/models/srv_models"

// ConfigLoader handles loading and validating configuration files
type ConfigLoader struct {
	configPath string
	config     *srv_models.Config
}
