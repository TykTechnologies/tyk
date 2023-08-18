package gateway

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
)

// OpenAPIComponent represents a component in the OpenAPI document
type OpenAPIComponent struct {
	Name        string
	Description string
}

// GenerateOpenAPIDocument generates an OpenAPI document from the source code
func GenerateOpenAPIDocument() {
	// Define the generateComponents function
	generateComponents := func() []OpenAPIComponent {
 	// Implement the generateComponents function
 	generateComponents := func() []OpenAPIComponent {
 		// TODO: Use reflection to traverse the source code and generate the OpenAPI components
 		components := make([]OpenAPIComponent, 0)
 		// TODO: Add code to generate the OpenAPI components
 		return components
 	}
 	// Use reflection to traverse the source code and generate the OpenAPI components
 	components := generateComponents()
 	return components
	}
 // Use reflection to traverse the source code and generate the OpenAPI components
 components := generateComponents()

	// Generate the OpenAPI document
	doc := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":   "Tyk Gateway",
			"version": "1.0",
		},
		"paths": make(map[string]interface{}),
		"components": map[string]interface{}{
			"schemas": components,
		},
	}

	// Write the OpenAPI document to a file
	writeToFile(doc)
}

// writeToFile writes the OpenAPI document to a JSON file
func writeToFile(doc map[string]interface{}) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling OpenAPI document:", err)
		return
	}

	err = ioutil.WriteFile("openapi.json", data, 0644)
	if err != nil {
		fmt.Println("Error writing OpenAPI document to file:", err)
	}
}

