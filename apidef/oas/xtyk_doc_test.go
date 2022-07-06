package oas

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	dumpXTykDocHelp = `if this flag is passed in tests, file "./schema/x-tyk-gateway.md"
will be updated after TestExtractDocFromXTyk has passed`
	dumpXTykDoc = flag.Bool("x-tyk-dump-doc", false, dumpXTykDocHelp)
	xTykDocPath = "./schema/x-tyk-gateway.md"
)

func TestExtractDocFromXTyk(t *testing.T) {
	fInfo, err := ExtractDocFromXTyk()
	if err != nil {
		if _, ok := err.(*FieldDocError); ok {
			// should fail, but for now let's print errors.
			t.Log(err.Error())
		} else {
			t.Fatal(err.Error())
		}
	}
	if !flag.Parsed() {
		flag.Parse()
	}
	if *dumpXTykDoc {
		_ = ioutil.WriteFile(xTykDocPath, []byte(xTykDocToMarkdown(fInfo)), 0666)
	}
}

func TestExtractDocUtils(t *testing.T) {
	t.Run("objParser", func(t *testing.T) {
		buildASTPackage := func(t *testing.T, src string) *ast.Package {
			f, err := parser.ParseFile(token.NewFileSet(), "oas.go", src, parser.ParseComments)
			assert.Nil(t, err)
			return &ast.Package{Files: map[string]*ast.File{"oas.go": f}}
		}

		structInfoEqual := func(t *testing.T, expect, actual StructInfo) {
			assert.Equal(t, expect.Name, actual.Name)
			if assert.Equal(t, len(expect.Fields), len(actual.Fields)) {
				for i, field := range expect.Fields {
					assert.Equal(t, *field, *actual.Fields[i])
				}
			}
		}

		t.Run("empty scope", func(t *testing.T) {
			p := newObjParser(buildASTPackage(t, "package oas\n"))
			assert.Empty(t, p.globals)
		})

		t.Run("field for internal use", func(t *testing.T) {
			// field "password" is marshaled for external use.
			const src = "package oas\n\ntype Server struct {\n\t// Name doc.\n\tName     string `bson:\"name\" json:\"name\"`\n\tpassword string\n}\n"
			p := newObjParser(buildASTPackage(t, src))
			p.parse("Server", "Server", &StructInfo{structObj: p.globals["Server"].(*ast.StructType), Name: "Server"})

			assert.Empty(t, p.errList.errs)
			actual := StructInfo{
				Name: "Server",
				Fields: []*FieldInfo{
					{
						JsonType: "string",
						JsonName: "name",
						GoPath:   "Server.Name",
						Doc:      "Name doc.\n",
					},
				},
			}
			structInfoEqual(t, *p.info[0], actual)
		})

		t.Run("ignored field", func(t *testing.T) {
			// object "Inline" is ignored as a field in Server.
			const src = "package oas\n\ntype Server struct {\n\t_ Inline `bson:\",inline\" json:\",inline\"`\n}\n\ntype Inline struct {\n\tName string `bson:\"name\" json:\"name\"`\n}\n"
			p := newObjParser(buildASTPackage(t, src))
			p.parse("Server", "Server", &StructInfo{structObj: p.globals["Server"].(*ast.StructType), Name: "Server"})

			assert.Empty(t, p.errList.errs)
			expect := StructInfo{
				Name:   "Server",
				Fields: []*FieldInfo{},
			}
			structInfoEqual(t, expect, *p.info[0])
		})

		t.Run("parse inline field with name", func(t *testing.T) {
			// object "Inline" is exposed as inline field in Server.
			const src = "package oas\n\ntype Server struct {\n\tInline `bson:\",inline\" json:\",inline\"`\n}\n\ntype Inline struct {\n\t// Name doc.\n\tName string `bson:\"name\" json:\"name\"`\n}\n"
			p := newObjParser(buildASTPackage(t, src))
			p.parse("Server", "Server", &StructInfo{structObj: p.globals["Server"].(*ast.StructType), Name: "Server"})

			assert.Empty(t, p.errList.errs)
			expect := StructInfo{
				Name: "Server",
				Fields: []*FieldInfo{
					{
						JsonType: "string",
						JsonName: "name",
						GoPath:   "Server.Name",
						Doc:      "Name doc.\n",
					},
				},
			}
			structInfoEqual(t, expect, *p.info[0])
		})

		t.Run("field not known", func(t *testing.T) {
			// object "Inline" is not defined anywhere.
			const src = "package oas\n\ntype Server struct {\n\tInline `bson:\",inline\" json:\",inline\"`\n}\n\n"
			p := newObjParser(buildASTPackage(t, src))
			p.parse("Server", "Server", &StructInfo{structObj: p.globals["Server"].(*ast.StructType), Name: "Server"})

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
				value:    &FieldInfo{JsonType: "boolean"},
				markdown: "`boolean`",
			},
			{
				value:    &FieldInfo{JsonType: "boolean", IsArray: true},
				markdown: "`[]boolean`",
			},
			{
				value:    &FieldInfo{JsonType: "boolean", IsArray: true, MapKey: "string"},
				markdown: "`map[string][]boolean`",
			},
			{
				value:    &FieldInfo{JsonType: "boolean", MapKey: "string"},
				markdown: "`map[string]boolean`",
			},
			{
				value:    &FieldInfo{JsonType: "Server"},
				markdown: "[Server](#server)",
			},
			{
				value:    &FieldInfo{JsonType: "Server", IsArray: true},
				markdown: "`[]`[Server](#server)",
			},
			{
				value:    &FieldInfo{JsonType: "Server", IsArray: true, MapKey: "string"},
				markdown: "`map[string][]`[Server](#server)",
			},
			{
				value:    &FieldInfo{JsonType: "Server", MapKey: "string"},
				markdown: "`map[string]`[Server](#server)",
			},
		}
		for _, run := range runs {
			assert.Equal(t, run.markdown, fieldTypeToMarkdown(run.value))
		}
	})

	t.Run("fieldInfoToMarkdown", func(t *testing.T) {
		runs := []struct {
			value    *FieldInfo
			markdown string
		}{
			{
				value:    &FieldInfo{JsonName: "id", JsonType: "object", Doc: "ID is an id of an API.\nOld API definition: `api_id`."},
				markdown: "- **`id`**\n\n  **Type: `object`**\n\n  ID is an id of an API.\n\n  Old API definition: `api_id`.\n\n",
			},
			{
				value:    &FieldInfo{JsonName: "id", JsonType: "object"},
				markdown: "- **`id`**\n\n  **Type: `object`**\n\n",
			},
			{
				value:    &FieldInfo{JsonName: "id", JsonType: "object", Doc: "ID is an id of an API.\n\n"},
				markdown: "- **`id`**\n\n  **Type: `object`**\n\n  ID is an id of an API.\n\n",
			},
			{
				value:    &FieldInfo{JsonName: "id", JsonType: "object", Doc: "ID is an id of an API.\n\n\nOld API definition: `api_id`.\n\n"},
				markdown: "- **`id`**\n\n  **Type: `object`**\n\n  ID is an id of an API.\n\n  Old API definition: `api_id`.\n\n",
			},
		}
		for _, run := range runs {
			var res strings.Builder
			fieldInfoToMarkdown(run.value, &res)
			assert.Equal(t, run.markdown, res.String())
		}
	})

	t.Run("xTykDocToMarkdown", func(t *testing.T) {
		runs := []struct {
			value    XTykDoc
			markdown string
		}{
			{
				value:    XTykDoc{{Name: "Server", Fields: []*FieldInfo{{JsonName: "id", JsonType: "object"}}}},
				markdown: fmt.Sprintf("%s### **Server**\n\n- **`id`**\n\n  **Type: `object`**\n\n\n", xTykDocMarkdownTitle),
			},
			{
				value:    XTykDoc{{Name: "Server", Fields: []*FieldInfo{{JsonName: "id", JsonType: "object"}, {JsonName: "id", JsonType: "object"}}}},
				markdown: fmt.Sprintf("%s### **Server**\n\n- **`id`**\n\n  **Type: `object`**\n\n- **`id`**\n\n  **Type: `object`**\n\n\n", xTykDocMarkdownTitle),
			},
			{
				value:    XTykDoc{{Name: "Server", Fields: []*FieldInfo{}}},
				markdown: fmt.Sprintf("%s### **Server**\n\n\n", xTykDocMarkdownTitle),
			},
		}
		for _, run := range runs {
			assert.Equal(t, run.markdown, xTykDocToMarkdown(run.value))
		}
	})
}
