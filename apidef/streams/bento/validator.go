package bento

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
)

type ConfigValidator interface {
	Validate(document []byte) error
}

type ValidatorKind string

const (
	DefaultBentoConfigSchemaName string        = "bento-config-schema.json"
	DefaultValidator             ValidatorKind = "default-validator"
	EnableAll                    ValidatorKind = "enable-all"
)

var (
	schemaOnce sync.Once

	bentoSchemas = map[ValidatorKind][]byte{}
)

//go:embed schema/*
var schemaDir embed.FS

func loadBentoSchemas() error {
	load := func() error {
		members, err := schemaDir.ReadDir("schema")
		if err != nil {
			return fmt.Errorf("listing Bento schemas failed %w", err)
		}

		bentoSchemas = make(map[ValidatorKind][]byte)
		for _, member := range members {
			if member.IsDir() {
				continue
			}

			fileName := member.Name()
			if !strings.HasSuffix(fileName, ".json") {
				// It might be an AsyncAPI schema in YAML format, it is not supported yet.
				continue
			}

			// Load default Bento configuration schema
			if fileName == DefaultBentoConfigSchemaName {
				var data []byte
				data, err = schemaDir.ReadFile(filepath.Join("schema/", DefaultBentoConfigSchemaName))
				if err != nil {
					return err
				}
				bentoSchemas[DefaultValidator] = data
			}
		}
		return nil
	}

	var err error
	schemaOnce.Do(func() {
		err = load()
	})
	return err
}

type DefaultConfigValidator struct {
	schemaLoader gojsonschema.JSONLoader
}

func NewDefaultConfigValidator() (*DefaultConfigValidator, error) {
	err := loadBentoSchemas() // loads the schemas only one time
	if err != nil {
		return nil, err
	}

	schema := bentoSchemas[DefaultValidator]
	return &DefaultConfigValidator{
		schemaLoader: gojsonschema.NewBytesLoader(schema),
	}, nil
}

func (v *DefaultConfigValidator) Validate(document []byte) error {
	documentLoader := gojsonschema.NewBytesLoader(document)
	result, err := gojsonschema.Validate(v.schemaLoader, documentLoader)
	if err != nil {
		return err
	}
	if result.Valid() {
		return nil
	}

	combinedErr := &multierror.Error{}
	combinedErr.ErrorFormat = tykerrors.Formatter
	validationErrs := result.Errors()
	for _, validationErr := range validationErrs {
		combinedErr = multierror.Append(combinedErr, errors.New(validationErr.String()))
	}
	return combinedErr.ErrorOrNil()
}

// EnableAllConfigValidator is a validator that skips all validation
type EnableAllConfigValidator struct{}

// NewEnableAllConfigValidator creates a new validator that skips all validation
func NewEnableAllConfigValidator() *EnableAllConfigValidator {
	return &EnableAllConfigValidator{}
}

// Validate always returns nil, effectively enabling all configurations
func (v *EnableAllConfigValidator) Validate(_ []byte) error {
	return nil
}
