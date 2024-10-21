package bento

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/TykTechnologies/gojsonschema"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/hashicorp/go-multierror"
)

type ConfigValidator interface {
	Validate(document []byte) error
}

const (
	DefaultBentoConfiguration = "default-bento-configuration"
)

var (
	schemaOnce sync.Once

	bentoSchemas = map[string][]byte{}
)

//go:embed schema/*
var schemaDir embed.FS

func loadBentoSchemas() error {
	load := func() error {
		members, err := schemaDir.ReadDir("schema")
		if err != nil {
			return fmt.Errorf("listing Bento schemas failed %w", err)
		}

		bentoSchemas = make(map[string][]byte)
		for _, member := range members {
			if member.IsDir() {
				continue
			}

			fileName := member.Name()
			if !strings.HasSuffix(fileName, ".json") {
				// It might be an AsyncAPI schema in YAML format, it is not supported yet.
				continue
			}

			// Load DefaultBentoConfiguration schema
			defaultBentoConfigurationSchemaFileName := DefaultBentoConfiguration + ".json"
			if fileName == defaultBentoConfigurationSchemaFileName {
				var data []byte
				data, err = schemaDir.ReadFile(filepath.Join("schema/", defaultBentoConfigurationSchemaFileName))
				if err != nil {
					return err
				}
				bentoSchemas[DefaultBentoConfiguration] = data
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

type DefaultBentoConfigValidator struct {
	schemaLoader gojsonschema.JSONLoader
}

func NewDefaultBentoConfigValidator() (*DefaultBentoConfigValidator, error) {
	err := loadBentoSchemas() // loads the schemas only one time
	if err != nil {
		return nil, err
	}

	schema := bentoSchemas[DefaultBentoConfiguration]
	return &DefaultBentoConfigValidator{
		schemaLoader: gojsonschema.NewBytesLoader(schema),
	}, nil
}

func (v *DefaultBentoConfigValidator) Validate(document []byte) error {
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
