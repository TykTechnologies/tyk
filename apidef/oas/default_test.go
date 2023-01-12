package oas

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestOAS_BuildDefaultTykExtension(t *testing.T) {
	t.Parallel()

	t.Run("build tyk extension with no supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{}, true)
		assert.NoError(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/",
					Strip: true,
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("build tyk extension with supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		customDomain := &Domain{
			Name:    "custom-domain.org",
			Enabled: true,
		}
		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:   "/listen-api",
			UpstreamURL:  "https://example.org/api",
			CustomDomain: customDomain.Name,
		}, true)

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
					Strip: true,
				},
				CustomDomain: customDomain,
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("do not override existing tyk extension by default", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{}, true)
		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
					Strip: true,
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("override existing tyk extension with supplied params", func(t *testing.T) {
		const (
			testSSMyAuth        = "my_auth"
			testSSMyAuthWithAnd = "my_auth_with_and"
			testSSMyAuthWithOR  = "my_auth_with_or"
			testHeader          = "my-header"
		)
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Security: openapi3.SecurityRequirements{
					{testSSMyAuth: []string{}, testSSMyAuthWithAnd: []string{}},
					{testSSMyAuthWithOR: []string{}},
				},
				Components: openapi3.Components{
					SecuritySchemes: openapi3.SecuritySchemes{
						testSSMyAuth: &openapi3.SecuritySchemeRef{
							Value: openapi3.NewSecurityScheme().WithType(typeAPIKey).WithIn(header).WithName(testHeader),
						},
						testSSMyAuthWithAnd: &openapi3.SecuritySchemeRef{
							Value: openapi3.NewSecurityScheme().WithType(typeOAuth2),
						},
						testSSMyAuthWithOR: &openapi3.SecuritySchemeRef{
							Value: openapi3.NewSecurityScheme().WithType(typeHTTP).WithScheme(schemeBasic),
						},
					},
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
					Strip: true,
				},
				CustomDomain: &Domain{true, "custom-domain.org"},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		newCustomDomain := &Domain{true, "new-custom-domain.org"}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:     "/new-listen-api",
			UpstreamURL:    "https://example.org/api",
			Authentication: getBoolPointer(true),
			CustomDomain:   newCustomDomain.Name,
		}, true)

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-api",
					Strip: true,
				},
				CustomDomain: newCustomDomain,
				Authentication: &Authentication{
					Enabled:              true,
					BaseIdentityProvider: apidef.AuthToken,
					SecuritySchemes: SecuritySchemes{
						testSSMyAuth: &Token{
							Enabled: true,
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
								},
							},
						},
						testSSMyAuthWithAnd: &OAuth{
							Enabled: true,
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
									Name:    defaultAuthSourceName,
								},
							},
						},
					},
				},
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("error when supplied invalid upstreamURL param", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/new-listen-api",
			UpstreamURL: "invalid-url",
		}, true)
		assert.ErrorIs(t, err, errInvalidUpstreamURL)
	})

	t.Run("error when no supplied params and invalid URL in servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "/listen-api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{}, true)
		assert.ErrorIs(t, err, errInvalidServerURL)
	})

	t.Run("error when no supplied params and no servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{}, true)
		assert.ErrorIs(t, err, errEmptyServersObject)
	})

	t.Run("middlewares", func(t *testing.T) {
		trueVal, falseVal := true, false

		const (
			tykGetOperationID  = "petsGET"
			tykPostOperationID = "petsPOST"
			oasGetOperationID  = "getPets"
			oasPostOperationID = "postPets"
		)
		getOASDef := func(withOperationID bool, withValidResponses bool) OAS {
			oasDef := OAS{
				T: openapi3.T{
					Info: &openapi3.Info{
						Title: "OAS API",
					},
					Servers: openapi3.Servers{
						{
							URL: "https://example-org.com/api",
						},
					},
					Paths: openapi3.Paths{
						"/pets": {
							Get: &openapi3.Operation{
								Responses: openapi3.Responses{},
							},
							Post: &openapi3.Operation{
								Responses: openapi3.Responses{},
							},
						},
					},
				},
			}

			var responses = make(openapi3.Responses)
			if withValidResponses {
				responses["200"] = &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Content: map[string]*openapi3.MediaType{
							"application/json": {
								Example: map[string]interface{}{"status": "ok"},
							},
						},
					},
				}
			}

			oasDef.Paths = openapi3.Paths{
				"/pets": {
					Get: &openapi3.Operation{
						Responses: responses,
					},
					Post: &openapi3.Operation{
						Responses: responses,
					},
				},
			}

			if withOperationID {
				oasDef.Paths["/pets"].Get.OperationID = oasGetOperationID
				oasDef.Paths["/pets"].Post.OperationID = oasPostOperationID
			}

			return oasDef
		}

		fillReqBody := func(oasDef *OAS, path, method string) {
			pathItem := oasDef.Paths.Find(path)
			oasOperation := pathItem.GetOperation(method)
			reqBody := openapi3.NewRequestBody()
			reqBody.Description = "JSON req body"
			valueSchema := openapi3.NewSchema()
			valueSchema.Properties = openapi3.Schemas{
				"value": {
					Value: &openapi3.Schema{
						Type: openapi3.TypeBoolean,
					},
				},
			}
			content := openapi3.NewContentWithSchema(valueSchema, []string{contentTypeJSON})
			reqBody.Content = content
			oasOperation.RequestBody = &openapi3.RequestBodyRef{Value: reqBody}
		}

		getExpectedOperations := func(enabled, oasOperationID bool, middlewares ...string) Operations {
			operations := make(Operations)
			for _, middleware := range middlewares {
				switch middleware {
				case middlewareAllowList:
					allowance := &Allowance{Enabled: enabled}
					if oasOperationID {
						if len(operations) > 0 {
							operations[oasGetOperationID].Allow = allowance
							operations[oasPostOperationID].Allow = allowance
						} else {
							operations = Operations{
								oasGetOperationID:  {Allow: allowance},
								oasPostOperationID: {Allow: allowance},
							}
						}
					} else {
						if len(operations) > 0 {
							operations[tykGetOperationID].Allow = allowance
							operations[tykPostOperationID].Allow = allowance
						} else {
							operations = Operations{
								tykGetOperationID:  {Allow: allowance},
								tykPostOperationID: {Allow: allowance},
							}
						}
					}
				case middlewareValidateRequest:
					validateRequest := &ValidateRequest{
						Enabled:           enabled,
						ErrorResponseCode: http.StatusUnprocessableEntity,
					}
					if oasOperationID {
						if len(operations) > 0 {
							operations[oasPostOperationID].ValidateRequest = validateRequest
						} else {
							operations = Operations{oasPostOperationID: {ValidateRequest: validateRequest}}
						}
					} else {
						if len(operations) > 0 {
							operations[tykPostOperationID].ValidateRequest = validateRequest
						} else {
							operations = Operations{tykPostOperationID: {ValidateRequest: validateRequest}}
						}
					}
				case middlewareMockResponse:
					mockResponse := &MockResponse{
						Enabled:         enabled,
						FromOASExamples: &FromOASExamples{Enabled: enabled},
					}
					if oasOperationID {
						if len(operations) > 0 {
							operations[oasGetOperationID].MockResponse = mockResponse
							operations[oasPostOperationID].MockResponse = mockResponse
						} else {
							operations = Operations{
								oasGetOperationID:  {MockResponse: mockResponse},
								oasPostOperationID: {MockResponse: mockResponse},
							}
						}
					} else {
						if len(operations) > 0 {
							operations[tykGetOperationID].MockResponse = mockResponse
							operations[tykPostOperationID].MockResponse = mockResponse
						} else {
							operations = Operations{
								tykGetOperationID:  {MockResponse: mockResponse},
								tykPostOperationID: {MockResponse: mockResponse},
							}
						}

					}
				}
			}

			return operations
		}

		t.Run("allowList", func(t *testing.T) {
			t.Run("enable allowList for all paths when no configured operationID in OAS", func(t *testing.T) {
				oasDef := getOASDef(false, false)
				expectedOperations := getExpectedOperations(true, false, middlewareAllowList)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &trueVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("enable allowList for all paths when operationID is configured in OAS", func(t *testing.T) {
				oasDef := getOASDef(true, false)

				expectedOperations := getExpectedOperations(true, true, middlewareAllowList)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &trueVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("disable allowList for all paths when no configured operationID in OAS", func(t *testing.T) {
				oasDef := getOASDef(false, false)

				expectedOperations := getExpectedOperations(false, false, middlewareAllowList)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &falseVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("disable allowList for all paths when operationID is configured in OAS", func(t *testing.T) {
				oasDef := getOASDef(true, false)

				expectedOperations := getExpectedOperations(false, true, middlewareAllowList)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &falseVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("override allowList (disable) configured in tyk extension - do not toggle block list if any", func(t *testing.T) {
				oasDef := getOASDef(true, false)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							oasGetOperationID: {
								Allow: &Allowance{
									Enabled: true,
								},
								Block: &Allowance{
									Enabled: false,
								},
							},
							oasPostOperationID: {
								Allow: &Allowance{
									Enabled: true,
								},
								Block: &Allowance{
									Enabled: false,
								},
							},
						},
					},
				}

				expectedOperations := Operations{
					oasGetOperationID: {
						Allow: &Allowance{
							Enabled: false,
						},
						Block: &Allowance{
							Enabled: false,
						},
					},
					oasPostOperationID: {
						Allow: &Allowance{
							Enabled: false,
						},
						Block: &Allowance{
							Enabled: false,
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &falseVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)

				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("override allowList (enable) configured in tyk extension - toggle enabled block list if any", func(t *testing.T) {
				oasDef := getOASDef(true, false)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							oasGetOperationID: {
								Allow: &Allowance{
									Enabled: false,
								},
								Block: &Allowance{
									Enabled: true,
								},
							},
							oasPostOperationID: {
								Allow: &Allowance{
									Enabled: false,
								},
							},
						},
					},
				}

				expectedOperations := Operations{
					oasGetOperationID: {
						Allow: &Allowance{
							Enabled: true,
						},
						Block: &Allowance{
							Enabled: false,
						},
					},
					oasPostOperationID: {
						Allow: &Allowance{
							Enabled: true,
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: &trueVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)

				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("do not configure allowList when parameter is not provided (nil)", func(t *testing.T) {
				oasDef := getOASDef(false, false)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							tykGetOperationID: {
								Allow: &Allowance{
									Enabled: false,
								},
							},
							tykPostOperationID: {
								Allow: &Allowance{
									Enabled: true,
								},
							},
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				var expectedOperations = make(Operations)
				for k, v := range tykExt.Middleware.Operations {
					expectedOperations[k] = v
				}

				tykExtensionConfigParams := TykExtensionConfigParams{
					AllowList: nil,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.EqualValues(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})
		})

		t.Run("validateRequest", func(t *testing.T) {
			t.Run("do not configure validateRequest for paths where request body is not specified for application/json",
				func(t *testing.T) {
					oasDef := getOASDef(false, false)
					fillReqBody(&oasDef, "/pets", http.MethodPost)

					expectedOperations := getExpectedOperations(true, false, middlewareValidateRequest)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &trueVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.EqualValues(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("enable validateRequest for all paths with application/json req body when no configured operationID in OAS",
				func(t *testing.T) {
					oasDef := getOASDef(false, false)
					fillReqBody(&oasDef, "/pets", http.MethodPost)

					expectedOperations := getExpectedOperations(true, false, middlewareValidateRequest)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &trueVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("enable validateRequest for all paths with application/json req body when operationID is configured in OAS",
				func(t *testing.T) {
					oasDef := getOASDef(true, false)
					fillReqBody(&oasDef, "/pets", http.MethodPost)

					expectedOperations := getExpectedOperations(true, true, middlewareValidateRequest)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &trueVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("disable validateRequest for all paths with application/json req body when no configured operationID in OAS",
				func(t *testing.T) {
					oasDef := getOASDef(false, false)
					fillReqBody(&oasDef, "/pets", http.MethodPost)
					expectedOperations := getExpectedOperations(false, false, middlewareValidateRequest)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &falseVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("disable validateRequest for all paths with application/json req body when operationID is configured in OAS",
				func(t *testing.T) {
					oasDef := getOASDef(true, false)
					fillReqBody(&oasDef, "/pets", http.MethodPost)

					expectedOperations := getExpectedOperations(false, true, middlewareValidateRequest)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &falseVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("override validateRequest configured in tyk extension", func(t *testing.T) {
				oasDef := getOASDef(true, false)
				fillReqBody(&oasDef, "/pets", http.MethodPost)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							oasPostOperationID: {
								ValidateRequest: &ValidateRequest{
									Enabled: false,
								},
							},
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				expectedOperations := getExpectedOperations(true, true, middlewareValidateRequest)

				tykExtensionConfigParams := TykExtensionConfigParams{
					ValidateRequest: &trueVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)

				assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})

			t.Run("do not configure validateRequest when parameter is not provided (nil)", func(t *testing.T) {
				oasDef := getOASDef(true, false)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							oasGetOperationID: {
								ValidateRequest: &ValidateRequest{
									Enabled: true,
								},
								Allow: &Allowance{
									Enabled: false,
								},
							},
							oasPostOperationID: {
								ValidateRequest: &ValidateRequest{
									Enabled: false,
								},
								Allow: &Allowance{
									Enabled: true,
								},
							},
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				var expectedOperations = make(Operations)
				for k, v := range tykExt.Middleware.Operations {
					expectedOperations[k] = v
				}

				tykExtensionConfigParams := TykExtensionConfigParams{
					ValidateRequest: nil,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				actualTykExtension := oasDef.GetTykExtension()
				assert.EqualValues(t, expectedOperations, actualTykExtension.Middleware.Operations)
			})

			t.Run("do not configure validateRequest when no paths have application/json req body",
				func(t *testing.T) {
					oasDef := getOASDef(true, false)

					tykExtensionConfigParams := TykExtensionConfigParams{
						ValidateRequest: &falseVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Nil(t, oasDef.GetTykExtension().Middleware)
				})
		})

		t.Run("mockResponse", func(t *testing.T) {
			t.Run("do not configure MockResponse if no path contains responses", func(t *testing.T) {
				oasDef := getOASDef(false, false)
				tykExtensionConfigParams := TykExtensionConfigParams{
					MockResponse: &trueVal,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.Nil(t, oasDef.GetTykExtension().Middleware)
			})

			t.Run("do not configure MockResponse if no valid examples/example/schema found but configured response",
				func(t *testing.T) {
					oasDef := getOASDef(false, false)
					description := "description"
					simpleResponse := openapi3.Responses{
						"200": &openapi3.ResponseRef{
							Value: &openapi3.Response{
								Description: &description,
							},
						},
					}
					oasDef.Paths["/pets"].Get.Responses = simpleResponse
					oasDef.Paths["/pets"].Post.Responses = simpleResponse
					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &trueVal,
					}

					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Nil(t, oasDef.GetTykExtension().Middleware)
				})

			t.Run("enable oasMockResponse for all paths when operationID is configured in OAS with valid examples in response",
				func(t *testing.T) {
					oasDef := getOASDef(true, false)

					validResponseWithExamples := openapi3.Responses{
						"200": &openapi3.ResponseRef{
							Value: &openapi3.Response{
								Content: openapi3.Content{
									"application/json": {
										Examples: openapi3.Examples{
											"1": &openapi3.ExampleRef{
												Value: &openapi3.Example{Value: map[string]interface{}{"status": "ok"}},
											},
										},
									},
								},
							},
						},
					}
					oasDef.Paths["/pets"].Get.Responses = validResponseWithExamples
					oasDef.Paths["/pets"].Post.Responses = validResponseWithExamples
					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &trueVal,
					}

					expectedOperations := getExpectedOperations(true, true, middlewareMockResponse)
					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("enable oasMockResponse for all paths when operationID is configured in OAS with valid responses",
				func(t *testing.T) {
					oasDef := getOASDef(true, true)

					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &trueVal,
					}

					expectedOperations := getExpectedOperations(true, true, middlewareMockResponse)
					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("enable oasMockResponse for all paths when operationID is not configured in OAS with valid responses",
				func(t *testing.T) {
					oasDef := getOASDef(false, true)

					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &trueVal,
					}

					expectedOperations := getExpectedOperations(true, false, middlewareMockResponse)
					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("disable oasMockResponse for all paths when operationID is configured in OAS with valid responses",
				func(t *testing.T) {
					oasDef := getOASDef(true, true)

					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &falseVal,
					}

					expectedOperations := getExpectedOperations(false, true, middlewareMockResponse)
					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("disable oasMockResponse for all paths when operationID is not configured in OAS with valid responses",
				func(t *testing.T) {
					oasDef := getOASDef(false, true)

					tykExtensionConfigParams := TykExtensionConfigParams{
						MockResponse: &falseVal,
					}

					expectedOperations := getExpectedOperations(false, false, middlewareMockResponse)
					err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

					assert.NoError(t, err)
					assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
				})

			t.Run("do not configure oasMockResponse when parameter is not provided (nil)", func(t *testing.T) {
				oasDef := getOASDef(false, true)

				tykExt := XTykAPIGateway{
					Server: Server{
						ListenPath: ListenPath{
							Value: "/",
						},
					},
					Upstream: Upstream{
						URL: "https://example-org.com/api",
					},
					Info: Info{
						Name: "OAS API",
						State: State{
							Active: true,
						},
					},
					Middleware: &Middleware{
						Operations: Operations{
							tykGetOperationID: {
								MockResponse: &MockResponse{
									Enabled: false,
								},
							},
							tykPostOperationID: {
								MockResponse: &MockResponse{
									Enabled: true,
								},
							},
						},
					},
				}

				oasDef.SetTykExtension(&tykExt)

				var expectedOperations = make(Operations)
				for k, v := range tykExt.Middleware.Operations {
					expectedOperations[k] = v
				}

				tykExtensionConfigParams := TykExtensionConfigParams{
					MockResponse: nil,
				}

				err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

				assert.NoError(t, err)
				assert.EqualValues(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
			})
		})

		t.Run("enable all middlewares together - allowList, validateRequest, mockResponse", func(t *testing.T) {
			oasDef := getOASDef(false, true)
			fillReqBody(&oasDef, "/pets", http.MethodPost)
			expectedOperations := getExpectedOperations(true, false, middlewareAllowList,
				middlewareValidateRequest, middlewareMockResponse)

			tykExtensionConfigParams := TykExtensionConfigParams{
				AllowList:       &trueVal,
				ValidateRequest: &trueVal,
				MockResponse:    &trueVal,
			}

			err := oasDef.BuildDefaultTykExtension(tykExtensionConfigParams, true)

			assert.NoError(t, err)
			assert.Equal(t, expectedOperations, oasDef.GetTykExtension().Middleware.Operations)
		})
	})

	t.Run("do not configure upstream URL with servers when upstream URL params is not provided and "+
		"upstream URL in x-tyk in not empty", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
					Strip: true,
				},
			},
			Upstream: Upstream{
				URL: "https://upstream.org/api",
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		newListenPath := "/new-listen-api"

		expectedTykExtension := existingTykExtension
		expectedTykExtension.Server.ListenPath.Value = newListenPath
		expectedTykExtension.Info.State.Active = true

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath: newListenPath,
		}, true)
		assert.NoError(t, err)
		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("do not configure state active, internal or strip listen path when not importing", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{}, false)
		assert.NoError(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/",
					Strip: false,
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active:   false,
					Internal: false,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})
}

func TestGetTykExtensionConfigParams(t *testing.T) {
	trueVal, falseVal := true, false
	t.Run("extract all params when provided", func(t *testing.T) {
		endpoint, err := url.Parse("/")
		assert.NoError(t, err)

		listenPath := "/listen-api"
		upstreamURL := "https://upstream.org"
		customDomain := "custom-domain.org"

		queryParams := endpoint.Query()
		queryParams.Set("listenPath", listenPath)
		queryParams.Set("upstreamURL", upstreamURL)
		queryParams.Set("customDomain", customDomain)
		queryParams.Set("validateRequest", "true")
		queryParams.Set("authentication", "true")
		queryParams.Set("allowList", "false")
		queryParams.Set("mockResponse", "true")

		endpoint.RawQuery = queryParams.Encode()
		r, err := http.NewRequest(http.MethodPatch, endpoint.String(), nil)
		assert.NoError(t, err)

		tykExtConfigParams := GetTykExtensionConfigParams(r)

		expectedConfigParams := TykExtensionConfigParams{
			ListenPath:      listenPath,
			UpstreamURL:     upstreamURL,
			CustomDomain:    customDomain,
			Authentication:  &trueVal,
			AllowList:       &falseVal,
			ValidateRequest: &trueVal,
			MockResponse:    &trueVal,
		}

		assert.Equal(t, &expectedConfigParams, tykExtConfigParams)
	})

	t.Run("nil when no params provided", func(t *testing.T) {
		endpoint, err := url.Parse("/")
		assert.NoError(t, err)

		r, err := http.NewRequest(http.MethodPatch, endpoint.String(), nil)
		assert.NoError(t, err)

		assert.Nil(t, GetTykExtensionConfigParams(r))
	})

	t.Run("nil for middleware when params not provided", func(t *testing.T) {
		endpoint, err := url.Parse("/")
		assert.NoError(t, err)

		listenPath := "/listen-api"
		upstreamURL := "https://upstream.org"
		customDomain := "custom-domain.org"

		queryParams := endpoint.Query()
		queryParams.Set("listenPath", listenPath)
		queryParams.Set("upstreamURL", upstreamURL)
		queryParams.Set("customDomain", customDomain)

		endpoint.RawQuery = queryParams.Encode()
		r, err := http.NewRequest(http.MethodPatch, endpoint.String(), nil)
		assert.NoError(t, err)

		tykExtConfigParams := GetTykExtensionConfigParams(r)

		expectedConfigParams := TykExtensionConfigParams{
			ListenPath:   listenPath,
			UpstreamURL:  upstreamURL,
			CustomDomain: customDomain,
		}

		assert.Equal(t, &expectedConfigParams, tykExtConfigParams)
	})

	t.Run("not nil when at least one parameter is provided", func(t *testing.T) {
		endpoint, err := url.Parse("/")
		assert.NoError(t, err)

		queryParams := endpoint.Query()
		queryParams.Set("allowList", "true")

		endpoint.RawQuery = queryParams.Encode()
		r, err := http.NewRequest(http.MethodPatch, endpoint.String(), nil)
		assert.NoError(t, err)

		tykExtConfigParams := GetTykExtensionConfigParams(r)

		expectedConfigParams := TykExtensionConfigParams{
			AllowList: &trueVal,
		}

		assert.Equal(t, &expectedConfigParams, tykExtConfigParams)
	})
}

func TestOAS_importAuthentication(t *testing.T) {
	const (
		testSecurityNameToken = "my_auth_token"
		testSecurityNameJWT   = "my_auth_jwt"
		testHeaderName        = "my-auth-token-header"
		testCookieName        = "my-auth-token-cookie"
	)

	t.Run("security is empty", func(t *testing.T) {
		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{})

		err := oas.importAuthentication(true)
		assert.ErrorIs(t, errEmptySecurityObject, err)

		authentication := oas.getTykAuthentication()
		assert.Nil(t, authentication)
	})

	t.Run("add first authentication in case of OR condition", func(t *testing.T) {
		check := func(t *testing.T, enable bool) {
			oas := OAS{}
			oas.Security = openapi3.SecurityRequirements{
				{testSecurityNameToken: []string{}},
				{testSecurityNameJWT: []string{}},
			}

			tokenScheme := openapi3.NewSecurityScheme()
			tokenScheme.Type = typeAPIKey
			tokenScheme.In = cookie
			tokenScheme.Name = testCookieName

			jwtScheme := openapi3.NewSecurityScheme()
			jwtScheme.Type = typeHTTP
			jwtScheme.Scheme = schemeBearer
			jwtScheme.BearerFormat = bearerFormatJWT

			oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
				testSecurityNameToken: &openapi3.SecuritySchemeRef{
					Value: tokenScheme,
				},
				testSecurityNameJWT: &openapi3.SecuritySchemeRef{
					Value: jwtScheme,
				},
			}

			oas.SetTykExtension(&XTykAPIGateway{})

			err := oas.importAuthentication(enable)
			assert.NoError(t, err)

			authentication := oas.getTykAuthentication()

			assert.Equal(t, enable, authentication.Enabled)

			expectedSecuritySchemes := SecuritySchemes{
				testSecurityNameToken: &Token{
					Enabled: enable,
					AuthSources: AuthSources{
						Cookie: &AuthSource{
							Enabled: true,
						},
					},
				},
			}

			assert.Equal(t, expectedSecuritySchemes, authentication.SecuritySchemes)
			assert.Equal(t, apidef.AuthTypeNone, authentication.BaseIdentityProvider)
		}

		t.Run("enable=true", func(t *testing.T) {
			check(t, true)
		})

		t.Run("enable=false", func(t *testing.T) {
			check(t, false)
		})
	})

	t.Run("update existing one", func(t *testing.T) {
		oas := OAS{}
		oas.Security = openapi3.SecurityRequirements{
			{testSecurityNameToken: []string{}},
		}

		securityScheme := openapi3.NewSecurityScheme()
		securityScheme.Type = typeAPIKey
		securityScheme.In = cookie
		securityScheme.Name = testCookieName

		oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
			testSecurityNameToken: &openapi3.SecuritySchemeRef{
				Value: securityScheme,
			},
		}

		xTykAPIGateway := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						testSecurityNameToken: &Token{
							Enabled: false,
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
									Name:    testHeaderName,
								},
							},
						},
					},
				},
			},
		}

		oas.SetTykExtension(xTykAPIGateway)

		err := oas.importAuthentication(true)
		assert.NoError(t, err)

		authentication := oas.getTykAuthentication()

		assert.True(t, authentication.Enabled)

		expectedSecuritySchemes := SecuritySchemes{
			testSecurityNameToken: &Token{
				Enabled: true,
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
						Name:    testHeaderName,
					},
					Cookie: &AuthSource{
						Enabled: true,
					},
				},
			},
		}

		assert.Equal(t, expectedSecuritySchemes, authentication.SecuritySchemes)
	})

	t.Run("add multiple authentication with AND condition", func(t *testing.T) {
		check := func(t *testing.T, enable bool) {
			oas := OAS{}
			oas.Security = openapi3.SecurityRequirements{
				{testSecurityNameToken: []string{}, testSecurityNameJWT: []string{}},
			}

			tokenScheme := openapi3.NewSecurityScheme()
			tokenScheme.Type = typeAPIKey
			tokenScheme.In = cookie
			tokenScheme.Name = testCookieName

			jwtScheme := openapi3.NewSecurityScheme()
			jwtScheme.Type = typeHTTP
			jwtScheme.Scheme = schemeBearer
			jwtScheme.BearerFormat = bearerFormatJWT

			oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
				testSecurityNameToken: &openapi3.SecuritySchemeRef{
					Value: tokenScheme,
				},
				testSecurityNameJWT: &openapi3.SecuritySchemeRef{
					Value: jwtScheme,
				},
			}

			oas.SetTykExtension(&XTykAPIGateway{})

			err := oas.importAuthentication(enable)
			assert.NoError(t, err)

			authentication := oas.getTykAuthentication()

			assert.Equal(t, enable, authentication.Enabled)

			expectedSecuritySchemes := SecuritySchemes{
				testSecurityNameToken: &Token{
					Enabled: enable,
					AuthSources: AuthSources{
						Cookie: &AuthSource{
							Enabled: true,
						},
					},
				},
				testSecurityNameJWT: &JWT{
					Enabled: enable,
					AuthSources: AuthSources{
						Header: &AuthSource{
							Enabled: true,
							Name:    defaultAuthSourceName,
						},
					},
				},
			}

			assert.Equal(t, expectedSecuritySchemes, authentication.SecuritySchemes)
			assert.Equal(t, apidef.AuthToken, authentication.BaseIdentityProvider)
		}

		t.Run("enable=true", func(t *testing.T) {
			check(t, true)
		})

		t.Run("enable=false", func(t *testing.T) {
			check(t, false)
		})
	})
}

func TestSecuritySchemes_Import(t *testing.T) {
	const (
		testSecurityNameToken       = "my_auth_token"
		testSecurityNameJWT         = "my_auth_jwt"
		testSecurityNameBasic       = "my_auth_basic"
		testSecurityNameOauth       = "my_auth_oauth"
		testSecurityNameUnsupported = "my_auth_unsupported"
		testHeaderName              = "my-auth-token-header"
		testCookieName              = "my-auth-token-cookie"
	)

	t.Run("token", func(t *testing.T) {
		check := func(t *testing.T, enable bool) {
			securitySchemes := SecuritySchemes{}
			nativeSecurityScheme := &openapi3.SecurityScheme{
				Type: typeAPIKey,
				In:   header,
				Name: testHeaderName,
			}

			err := securitySchemes.Import(testSecurityNameToken, nativeSecurityScheme, enable)
			assert.NoError(t, err)

			expectedToken := &Token{
				Enabled: enable,
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
					},
				},
			}

			assert.Equal(t, expectedToken, securitySchemes[testSecurityNameToken])
		}

		t.Run("enable=true", func(t *testing.T) {
			check(t, true)
		})

		t.Run("enable=false", func(t *testing.T) {
			check(t, false)
		})
	})

	t.Run("jwt", func(t *testing.T) {
		securitySchemes := SecuritySchemes{}
		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type:         typeHTTP,
			Scheme:       schemeBearer,
			BearerFormat: bearerFormatJWT,
		}

		err := securitySchemes.Import(testSecurityNameJWT, nativeSecurityScheme, true)
		assert.NoError(t, err)

		expectedJWT := &JWT{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
					Name:    defaultAuthSourceName,
				},
			},
		}

		assert.Equal(t, expectedJWT, securitySchemes[testSecurityNameJWT])
	})

	t.Run("basic", func(t *testing.T) {
		securitySchemes := SecuritySchemes{}
		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type:   typeHTTP,
			Scheme: schemeBasic,
		}

		err := securitySchemes.Import(testSecurityNameBasic, nativeSecurityScheme, true)
		assert.NoError(t, err)

		expectedBasic := &Basic{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
					Name:    defaultAuthSourceName,
				},
			},
		}

		assert.Equal(t, expectedBasic, securitySchemes[testSecurityNameBasic])
	})

	t.Run("oauth", func(t *testing.T) {
		securitySchemes := SecuritySchemes{}
		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type: typeOAuth2,
		}

		err := securitySchemes.Import(testSecurityNameOauth, nativeSecurityScheme, true)
		assert.NoError(t, err)

		expectedOAuth := &OAuth{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
					Name:    defaultAuthSourceName,
				},
			},
		}

		assert.Equal(t, expectedOAuth, securitySchemes[testSecurityNameOauth])
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		securitySchemes := SecuritySchemes{}
		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type: "unknown",
		}

		err := securitySchemes.Import(testSecurityNameUnsupported, nativeSecurityScheme, true)
		assert.Error(t, err, fmt.Sprintf(unsupportedSecuritySchemeFmt, testSecurityNameUnsupported))
	})

	t.Run("update existing one", func(t *testing.T) {
		existingToken := &Token{
			AuthSources: AuthSources{
				Cookie: &AuthSource{
					Enabled: true,
					Name:    testCookieName,
				},
			},
		}
		securitySchemes := SecuritySchemes{
			testSecurityNameToken: existingToken,
		}

		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type: typeAPIKey,
			In:   header,
			Name: testHeaderName,
		}

		err := securitySchemes.Import(testSecurityNameToken, nativeSecurityScheme, true)
		assert.NoError(t, err)

		expectedToken := &Token{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
				},
				Cookie: &AuthSource{
					Enabled: true,
					Name:    testCookieName,
				},
			},
		}

		assert.Equal(t, expectedToken, securitySchemes[testSecurityNameToken])
	})
}

func TestSecuritySchemes_GetBaseIdentityProvider(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		ss := SecuritySchemes{}
		t.Run("zero", func(t *testing.T) {
			assert.Equal(t, apidef.AuthTypeNone, ss.GetBaseIdentityProvider())
		})

		ss["token"] = &Token{}

		t.Run("one", func(t *testing.T) {
			assert.Equal(t, apidef.AuthTypeNone, ss.GetBaseIdentityProvider())
		})
	})

	ss := SecuritySchemes{}
	ss["token"] = &Token{}
	ss["jwt"] = &JWT{}
	ss["oauth"] = &OAuth{}
	ss["basic"] = &Basic{}

	t.Run("token", func(t *testing.T) {
		assert.Equal(t, apidef.AuthToken, ss.GetBaseIdentityProvider())
	})

	delete(ss, "token")

	t.Run("jwt", func(t *testing.T) {
		assert.Equal(t, apidef.JWTClaim, ss.GetBaseIdentityProvider())
	})

	delete(ss, "jwt")

	t.Run("oauth", func(t *testing.T) {
		assert.Equal(t, apidef.OAuthKey, ss.GetBaseIdentityProvider())
	})
}

func TestToken_Import(t *testing.T) {
	const testHeaderName = "my-auth-token-header"
	const testCookieName = "my-auth-token-cookie"

	token := &Token{
		AuthSources: AuthSources{
			Cookie: &AuthSource{
				Enabled: true,
				Name:    testCookieName,
			},
		},
	}

	nativeSecurityScheme := &openapi3.SecurityScheme{
		Type: typeAPIKey,
		In:   header,
		Name: testHeaderName,
	}

	token.Import(nativeSecurityScheme, true)

	expectedToken := &Token{
		Enabled: true,
		AuthSources: AuthSources{
			Header: &AuthSource{
				Enabled: true,
			},
			Cookie: &AuthSource{
				Enabled: true,
				Name:    testCookieName,
			},
		},
	}

	assert.Equal(t, expectedToken, token)
}

func TestAuthSources_Import(t *testing.T) {
	expectedAuthSource := &AuthSource{Enabled: true}

	t.Run(header, func(t *testing.T) {
		as := AuthSources{}
		as.Import(header)

		assert.Equal(t, expectedAuthSource, as.Header)
	})

	t.Run(query, func(t *testing.T) {
		as := AuthSources{}
		as.Import(query)

		assert.Equal(t, expectedAuthSource, as.Query)
	})

	t.Run(cookie, func(t *testing.T) {
		as := AuthSources{}
		as.Import(cookie)

		assert.Equal(t, expectedAuthSource, as.Cookie)
	})
}

func TestJWT_Import(t *testing.T) {
	jwt := &JWT{}
	jwt.Import(true)

	expectedJWT := &JWT{Enabled: true}
	expectedJWT.Header = &AuthSource{true, defaultAuthSourceName}

	assert.Equal(t, expectedJWT, jwt)
}

func TestBasic_Import(t *testing.T) {
	basic := &Basic{}
	basic.Import(true)

	expectedBasic := &Basic{Enabled: true}
	expectedBasic.Header = &AuthSource{true, defaultAuthSourceName}

	assert.Equal(t, expectedBasic, basic)
}

func TestOAuth_Import(t *testing.T) {
	oauth := &OAuth{}
	oauth.Import(true)

	expectedOAuth := &OAuth{Enabled: true}
	expectedOAuth.Header = &AuthSource{true, defaultAuthSourceName}

	assert.Equal(t, expectedOAuth, oauth)
}

func TestRetainOldServerURL(t *testing.T) {
	type args struct {
		oldServers openapi3.Servers
		newServers openapi3.Servers
	}
	tests := []struct {
		name string
		args args
		want openapi3.Servers
	}{
		{
			name: "empty old servers",
			args: args{
				oldServers: openapi3.Servers{},
				newServers: openapi3.Servers{
					{
						URL: "https://upstream.org/api",
					},
					{
						URL: "https://upstream.com/api",
					},
				},
			},
			want: openapi3.Servers{
				{
					URL: "https://upstream.org/api",
				},
				{
					URL: "https://upstream.com/api",
				},
			},
		},
		{
			name: "existing old servers",
			args: args{
				oldServers: openapi3.Servers{
					{
						URL: "https://tyk-gateway.com/api",
					},
					{
						URL: "https://upstream.xyz/api",
					},
				},
				newServers: openapi3.Servers{
					{
						URL: "https://upstream.org/api",
					},
					{
						URL: "https://upstream.com/api",
					},
				},
			},
			want: openapi3.Servers{
				{
					URL: "https://tyk-gateway.com/api",
				},
				{
					URL: "https://upstream.org/api",
				},
				{
					URL: "https://upstream.com/api",
				},
			},
		},
		{
			name: "duplicate in servers",
			args: args{
				oldServers: openapi3.Servers{
					{
						URL: "https://tyk-gateway.com/api",
					},
					{
						URL: "https://upstream.xyz/api",
					},
				},
				newServers: openapi3.Servers{
					{
						URL: "https://tyk-gateway.com/api",
					},
					{
						URL: "https://upstream.org/api",
					},
				},
			},
			want: openapi3.Servers{
				{
					URL: "https://tyk-gateway.com/api",
				},
				{
					URL: "https://upstream.org/api",
				},
			},
		},
		{
			name: "empty new servers",
			args: args{
				oldServers: openapi3.Servers{
					{
						URL: "https://tyk-gateway.com/api",
					},
					{
						URL: "https://upstream.xyz/api",
					},
				},
			},
			want: nil,
		},
		{
			name: "empty old servers",
			args: args{
				newServers: openapi3.Servers{
					{
						URL: "https://upstream.xyz/api",
					},
				},
			},
			want: openapi3.Servers{
				{
					URL: "https://upstream.xyz/api",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.EqualValues(t, tt.want, RetainOldServerURL(tt.args.oldServers, tt.args.newServers))
		})
	}
}
