package oas

//go:generate go test -run=TestExtractDocFromXTyk . -timeout 7s -v -x-tyk-dump-doc

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"reflect"
	"runtime"
	"strings"
)

type StructInfo struct {
	// Name is struct go name
	Name string
	// Fields holds information of the fields, if this object is a struct.
	Fields    []*FieldInfo    `json:"fields,omitempty"`
	structObj *ast.StructType `json:"-"`
}

type FieldInfo struct {
	// Doc is field docs. comments that are not part of docs are excluded.
	Doc string `json:"doc"`
	// JsonName is the corresponding json name of the field.
	JsonName string `json:"json_name"`
	// JsonType valid json type if it was found
	JsonType string `json:"json_type"`
	// GoPath is the go path of this field starting from root object
	GoPath string `json:"go_path"`
	// IsArray reports if this field is an array.
	IsArray bool `json:"is_array"`
}

type DocErrList struct {
	errs []string
}

func (err *DocErrList) Error() string {
	return strings.Join(err.errs, "\n")
}

func (err *DocErrList) WriteError(errMsg string) {
	if errMsg == "" {
		return
	}
	err.errs = append(err.errs, errMsg)
}

func (err *DocErrList) Empty() bool {
	return len(err.errs) == 0
}

// ExtractDocFromXTyk returns documentation associated with XTykAPIGateway struct or error.
// if err is of type *DocErrList, documentation may not be empty.
func ExtractDocFromXTyk() ([]*StructInfo, error) {
	_, thisFilePath, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("missing caller information")
	}

	fileSet := token.NewFileSet()
	pkgs, err := parser.ParseDir(fileSet, path.Dir(thisFilePath), filterXTykGoFile, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	const (
		rootStructName  = "XTykAPIGateway"
		rootJsonName    = "x-tyk-gateway"
		requiredPkgName = "oas"
	)
	if _, ok = pkgs[requiredPkgName]; !ok {
		return nil, fmt.Errorf("required package %s", requiredPkgName)
	}

	globals := map[string]ast.Expr{}
	for _, fileObj := range pkgs[requiredPkgName].Files {
		if fileObj.Scope == nil {
			continue
		}
		for objName, obj := range fileObj.Scope.Objects {
			if decl, ok := obj.Decl.(*ast.TypeSpec); ok && ast.IsExported(objName) {
				switch obj := decl.Type.(type) {
				case *ast.StructType:
					globals[objName] = obj
				case *ast.ArrayType:
					globals[objName] = obj
				}
			}
		}
	}

	rootStructInfo := &StructInfo{
		Name:      rootJsonName,
		structObj: globals[rootStructName].(*ast.StructType),
	}

	rootInfo := []*StructInfo{rootStructInfo}
	errList := &DocErrList{}
	visited := map[string]bool{}
	processXTykFields(&rootInfo, globals, visited, rootStructInfo, rootJsonName, errList)
	if errList.Empty() {
		return rootInfo, nil
	}
	return rootInfo, errList
}

func processXTykFields(info *[]*StructInfo, globals map[string]ast.Expr, visited map[string]bool, structInfo *StructInfo, goPath string, errList *DocErrList) {
	if visited[goPath] {
		return
	}
	visited[goPath] = true
	for _, field := range structInfo.structObj.Fields.List {
		ident := extractIdentFromExpr(field.Type)
		if ident == nil {
			if field.Names != nil {
				ident = extractIdentFromExpr(globals[field.Names[0].Name])
			}
			if ident == nil {
				errList.WriteError(fmt.Sprintf("identifier from %s is not known\n", goPath))
				continue
			}
		}

		jsonName, isInline := jsonTagFromBasicLit(field.Tag)
		if isInline {
			if !ident.IsExported() {
				continue
			}
			// for inline Global "struct", keep tree as it was but change the root struct
			if structObj, ok := globals[ident.Name].(*ast.StructType); ok {
				tempStructObj := structInfo.structObj
				structInfo.structObj = structObj
				processXTykFields(info, globals, visited, structInfo, goPath, errList)
				structInfo.structObj = tempStructObj
			} else {
				// field is inline and exported but was not scanned
				errList.WriteError(fmt.Sprintf("field %s.%s is declared but not found\n", goPath, ident.Name))
			}
		}

		if jsonName == "" {
			// field is for internal use?
			continue
		}

		var goName string
		if len(field.Names) == 0 {
			errList.WriteError(fmt.Sprintf("unidentified field in %s", goPath))
			continue
		} else {
			goName = field.Names[0].Name
		}

		docs := cleanDocs(field.Doc)
		if docs == "" {
			errList.WriteError(fmt.Sprintf("field %s.%s is missing documentation", goPath, goName))
		}

		fieldInfo := &FieldInfo{
			JsonName: jsonName,
			GoPath:   goPath + "." + goName,
			Doc:      docs,
			JsonType: goTypeToJson(globals, ident.Name),
			IsArray:  isExprArray(field.Type),
		}

		if globals[ident.Name] != nil {
			switch obj := globals[ident.Name].(type) {
			case *ast.StructType:
				newInfo := &StructInfo{structObj: obj, Name: ident.Name}
				*info = append(*info, newInfo)
				processXTykFields(info, globals, visited, newInfo, ident.Name, errList)
			case *ast.ArrayType:
				typeName := extractIdentFromExpr(obj).Name
				if structObj, ok := globals[typeName].(*ast.StructType); ok {
					newInfo := &StructInfo{structObj: structObj, Name: typeName}
					*info = append(*info, newInfo)
					fieldInfo.JsonType = typeName
					fieldInfo.IsArray = true
					processXTykFields(info, globals, visited, newInfo, typeName, errList)
				}
			}
		}

		structInfo.Fields = append(structInfo.Fields, fieldInfo)
	}
}

func cleanDocs(docs ...*ast.CommentGroup) string {
	s := strings.Builder{}
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		docText := doc.Text()
		for _, lineComment := range strings.Split(docText, "\n") {
			lineComment = strings.TrimLeft(lineComment, "/")
			lineComment = strings.TrimLeft(lineComment, "/*")
			lineComment = strings.TrimLeft(lineComment, "*\\")
			lineComment = strings.TrimSpace(lineComment)
			if lineComment != "" {
				s.WriteString(lineComment)
				s.WriteByte('\n')
			}
		}
	}
	return s.String()
}

func extractIdentFromExpr(expr ast.Expr) *ast.Ident {
	switch objType := expr.(type) {
	case *ast.StarExpr:
		if identType, ok := objType.X.(*ast.Ident); ok {
			if identType.IsExported() {
				return identType
			}
		}

	case *ast.Ident:
		return objType

	case *ast.ArrayType:
		return extractIdentFromExpr(objType.Elt)
	}
	return nil
}

func isExprArray(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.ArrayType:
		return true
	}
	return false
}

func jsonTagFromBasicLit(tag *ast.BasicLit) (jsonName string, isInline bool) {
	if tag == nil {
		return "", false
	}

	jsonTags := strings.Split(reflect.StructTag(tag.Value).Get("json"), ",")
	if len(jsonTags) == 0 {
		return "", false
	}

	if jsonTags[0] == "" || jsonTags[0] == "-" {
		return "", false
	}

	if len(jsonTags) > 1 && jsonTags[1] == "inline" {
		return jsonTags[0], true
	}

	return jsonTags[0], false
}

func filterXTykGoFile(fInfo fs.FileInfo) bool {
	ignoreList := map[string]bool{
		"default.go":   true,
		"oasutil.go":   true,
		"oas.go":       true,
		"validator.go": true,
		"x_tyk_doc.go": true,
	}
	return !(ignoreList[fInfo.Name()] || strings.HasSuffix(fInfo.Name(), "_test.go"))
}

func goTypeToJson(globals map[string]ast.Expr, typeName string) string {
	switch typeName {
	case "string":
		return "string"
	case "int", "uint", "int64", "uint64", "int32", "uint32":
		return "int"
	case "float", "float32":
		return "float"
	case "float64":
		return "double"
	case "bool":
		return "boolean"
	default:
		if _, ok := globals[typeName]; ok {
			return typeName
		}
	}
	return ""
}

func xtykDocToMarkdown(xtykDoc []*StructInfo) string {
	const title = `
## Documentation of X-Tyk-Gateway Object

`

	docWriter := strings.Builder{}
	docWriter.WriteString(title)

	for _, structInfo := range xtykDoc {
		docWriter.WriteString(fmt.Sprintf("### **%s**\n\n", structInfo.Name))

		for _, field := range structInfo.Fields {
			docWriter.WriteString(fmt.Sprintf("- `%s`\n\n", field.JsonName))

			if field.JsonType != "" {
				docWriter.WriteString("  **Type: ")
				docWriter.WriteString(fmt.Sprintf("%s**\n\n", jsonTypeToHTML(field.JsonType, field.IsArray)))
			}

			if field.Doc != "" {
				for _, doc := range strings.Split(field.Doc, "\n") {
					if doc != "" {
						docWriter.WriteString(fmt.Sprintf("  %s\n\n", doc))
					}
				}
			}

		}
		docWriter.WriteByte('\n')
	}
	return docWriter.String()
}

func jsonTypeToHTML(jsonType string, isArray bool) string {
	if jsonType == "" {
		return ""
	}

	if isArray {
		jsonType = "[]" + jsonType
	}

	typeName := strings.TrimPrefix(jsonType, "[]")
	switch typeName {
	case "boolean", "int", "float", "double", "string":
		return fmt.Sprintf("`%s`", jsonType)
	}
	// markdown link
	return fmt.Sprintf("[%s](#%s)", jsonType, typeName)
}
