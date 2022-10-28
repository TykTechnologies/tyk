package oas

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	dumpXTykDocHelp = `if this flag is passed in tests, file "./schema/x-tyk-gateway.md"
will be updated after TestExtractDocFromXTyk has passed`
	dumpXTykDoc = flag.Bool("x-tyk-dump-doc", false, dumpXTykDocHelp)
	xTykDocPath = "x-tyk-gateway.md"
)

func TestExtractDocFromXTyk(t *testing.T) {
	fInfo, err := ExtractDocFromXTyk()
	if err != nil {
		t.Fatal("\n" + err.Error())
	}
	if !flag.Parsed() {
		flag.Parse()
	}
	if *dumpXTykDoc {
		filename := path.Join("schema", xTykDocPath)
		t.Logf("Writing out: %s", filename)
		err = ioutil.WriteFile(filename, []byte(xTykDocToMarkdown(fInfo)), 0666)
		assert.NoError(t, err)
	} else {
		t.Log("Skipping writing out x-tyk-gateway.md docs")
	}
}

func TestExtractDocUtils(t *testing.T) {
	t.Run("objParser", func(t *testing.T) {
		buildASTPackage := func(t *testing.T, src string) (*ast.Package, *token.FileSet) {
			fs := token.NewFileSet()
			f, err := parser.ParseFile(fs, "oas.go", src, parser.ParseComments)
			assert.Nil(t, err)
			return &ast.Package{Files: map[string]*ast.File{"oas.go": f}}, fs
		}

		structInfoEqual := func(t *testing.T, expect, actual StructInfo) {
			t.Helper()
			assert.Equal(t, expect.Name, actual.Name)
			if assert.Equal(t, len(expect.Fields), len(actual.Fields)) {
				for i, field := range expect.Fields {
					assert.Equal(t, *field, *actual.Fields[i])
				}
			}
		}

		t.Run("empty scope", func(t *testing.T) {
			pkg, _ := buildASTPackage(t, "package oas\n")
			p := newObjParser(pkg)
			assert.Empty(t, p.globals)
		})

		t.Run("field for internal use", func(t *testing.T) {
			// field "password" is marshaled for external use.
			const src = "package oas\n\ntype Server struct {\n\t// Name doc.\n\tName     string `bson:\"name\" json:\"name\"`\n\tpassword string\n}\n"

			pkg, fs := buildASTPackage(t, src)

			p := newObjParser(pkg)
			p.parse("Server", "Server", &StructInfo{
				fileSet:   fs,
				structObj: p.globals["Server"].(*ast.StructType),
				Name:      "Server",
			})

			assert.Empty(t, p.errList.errs)
			actual := StructInfo{
				fileSet: fs,
				Name:    "Server",
				Fields: []*FieldInfo{
					{
						JSONType: "string",
						JSONName: "name",
						GoPath:   "Server.Name",
						Doc:      "Name doc.\n",
						fileSet:  fs,
					},
				},
			}
			structInfoEqual(t, *p.info[0], actual)
		})

		t.Run("ignored field", func(t *testing.T) {
			// object "Inline" is ignored as a field in Server.
			const src = "package oas\n\ntype Server struct {\n\t_ Inline `bson:\",inline\" json:\",inline\"`\n}\n\ntype Inline struct {\n\tName string `bson:\"name\" json:\"name\"`\n}\n"

			pkg, fs := buildASTPackage(t, src)

			p := newObjParser(pkg)
			p.parse("Server", "Server", &StructInfo{
				fileSet:   fs,
				structObj: p.globals["Server"].(*ast.StructType),
				Name:      "Server",
			})

			assert.Empty(t, p.errList.errs)
			expect := StructInfo{
				fileSet: fs,
				Name:    "Server",
				Fields:  []*FieldInfo{},
			}
			structInfoEqual(t, expect, *p.info[0])
		})

		t.Run("parse inline field with name", func(t *testing.T) {
			// object "Inline" is exposed as inline field in Server.
			const src = "package oas\n\ntype Server struct {\n\tInline `bson:\",inline\" json:\",inline\"`\n}\n\ntype Inline struct {\n\t// Name doc.\n\tName string `bson:\"name\" json:\"name\"`\n}\n"

			pkg, fs := buildASTPackage(t, src)

			p := newObjParser(pkg)
			p.parse("Server", "Server", &StructInfo{
				fileSet:   fs,
				structObj: p.globals["Server"].(*ast.StructType),
				Name:      "Server",
			})

			assert.Empty(t, p.errList.errs)
			expect := StructInfo{
				fileSet: fs,
				Name:    "Server",
				Fields: []*FieldInfo{
					{
						JSONType: "string",
						JSONName: "name",
						GoPath:   "Server.Name",
						Doc:      "Name doc.\n",
						fileSet:  fs,
					},
				},
			}
			structInfoEqual(t, expect, *p.info[0])
		})

		t.Run("field not known", func(t *testing.T) {
			// object "Inline" is not defined anywhere.
			const src = "package oas\n\ntype Server struct {\n\tInline `bson:\",inline\" json:\",inline\"`\n}\n\n"

			pkg, fs := buildASTPackage(t, src)

			p := newObjParser(pkg)
			p.parse("Server", "Server", &StructInfo{
				fileSet:   fs,
				structObj: p.globals["Server"].(*ast.StructType),
				Name:      "Server",
			})

			assert.ElementsMatch(t, p.errList.errs, []string{"field Server.Inline is declared but not found\n"})
			expect := StructInfo{
				Name:   "Server",
				Fields: []*FieldInfo{},
			}
			structInfoEqual(t, expect, *p.info[0])
		})
	})

	t.Run("jsonTagFromBasicLit", func(t *testing.T) {
		runs := []struct {
			value    *ast.BasicLit
			jsonName string
			isInline bool
		}{
			{
				value:    &ast.BasicLit{Value: `json:"id,omitempty"`},
				jsonName: "id",
			},
			{
				value:    &ast.BasicLit{Value: `json:"id"`},
				jsonName: "id",
			},
			{
				value: &ast.BasicLit{Value: `json:"-"`},
			},
			{
				value: &ast.BasicLit{},
			},
			{
				value: nil,
			},
			{
				value:    &ast.BasicLit{Value: `json:"id,inline"`},
				isInline: true,
			},
			{
				value:    &ast.BasicLit{Value: `json:"-,inline"`},
				isInline: true,
			},
			{
				value:    &ast.BasicLit{Value: `json:",inline"`},
				isInline: true,
			},
		}
		for _, run := range runs {
			jsonName, isInline := jsonTagFromBasicLit(run.value)
			assert.Equal(t, run.jsonName, jsonName)
			assert.Equal(t, run.isInline, isInline)
		}
	})

	t.Run("fieldTypeToMarkdown", func(t *testing.T) {
		runs := []struct {
			value    *FieldInfo
			markdown string
		}{
			{
				value:    &FieldInfo{JSONType: "boolean"},
				markdown: "`boolean`",
			},
			{
				value:    &FieldInfo{JSONType: "boolean", IsArray: true},
				markdown: "`[]boolean`",
			},
			{
				value:    &FieldInfo{JSONType: "boolean", IsArray: true, MapKey: "string"},
				markdown: "`map[string][]boolean`",
			},
			{
				value:    &FieldInfo{JSONType: "boolean", MapKey: "string"},
				markdown: "`map[string]boolean`",
			},
			{
				value:    &FieldInfo{JSONType: "Server"},
				markdown: "[Server](#server)",
			},
			{
				value:    &FieldInfo{JSONType: "Server", IsArray: true},
				markdown: "`[]`[Server](#server)",
			},
			{
				value:    &FieldInfo{JSONType: "Server", IsArray: true, MapKey: "string"},
				markdown: "`map[string][]`[Server](#server)",
			},
			{
				value:    &FieldInfo{JSONType: "Server", MapKey: "string"},
				markdown: "`map[string]`[Server](#server)",
			},
		}
		for _, run := range runs {
			assert.Equal(t, run.markdown, fieldTypeToMarkdown(run.value))
		}
	})
}
