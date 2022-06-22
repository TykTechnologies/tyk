package oas

//go:generate go test -run=TestExtractDocFromXTyk . -timeout 7s -x-tyk-dump-doc=schema/x-tyk-doc.json

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

type FieldInfo struct {
	// Doc is field docs. comments that are not part of docs are excluded.
	Doc string `json:"doc"`
	// JsonName is the corresponding field name in the json object.
	JsonName string `json:"json_name"`
	// Fields holds information of the fields, if this object is a struct.
	Fields []*FieldInfo `json:"fields,omitempty"`
	// JsonType valid json type if it was found
	JsonType string `json:"json_type"`
	// GoPath is the go path of this field starting from root object
	GoPath string `json:"go_name"`
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

// ExtractDocFromXTyk returns a *FieldInfo tree associated with XTykAPIGateway struct.
// the info is always nil if error is not nil.
// the returned tree is the same as expanding XTykAPIGateway struct.
func ExtractDocFromXTyk() (*FieldInfo, error) {
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

	structObjs := map[string]*ast.StructType{}
	for _, fileObj := range pkgs[requiredPkgName].Files {
		if fileObj.Scope == nil {
			continue
		}
		for objName, obj := range fileObj.Scope.Objects {
			if decl, ok := obj.Decl.(*ast.TypeSpec); ok && ast.IsExported(objName) {
				if structObj, ok := decl.Type.(*ast.StructType); ok {
					structObjs[objName] = structObj
				}
			}
		}
	}

	rootStruct := structObjs[rootStructName]
	if rootStruct == nil {
		return nil, fmt.Errorf("required struct %s", rootStructName)
	}

	rootInfo := &FieldInfo{
		JsonName: rootJsonName,
		JsonType: "object",
		GoPath:   rootStructName,
		Doc:      "root",
	}
	var errList DocErrList
	processXTykFields(rootInfo, structObjs, rootStruct, rootStructName, &errList)
	//if !errList.Empty() {
	//	return nil, &errList
	//}
	return rootInfo, &errList
}

func processXTykFields(info *FieldInfo, structObjs map[string]*ast.StructType, structObj *ast.StructType, goPath string, errList *DocErrList) {
	for _, field := range structObj.Fields.List {
		ident := extractIdentFromExpr(field.Type)
		if ident == nil {
			if field.Names != nil {
				ident = ast.NewIdent(field.Names[0].Name)
			} else {
				errList.WriteError(fmt.Sprintf("identifier from %s is not known\n", goPath))
			}
		}

		jsonName, isInline := jsonTagFromBasicLit(field.Tag)
		if isInline {
			if !ident.IsExported() {
				continue
			}
			// for inline Global "struct", keep tree as it was but change the root struct
			if structObjs[ident.Name] != nil {
				processXTykFields(info, structObjs, structObjs[ident.Name], goPath, errList)
			} else {
				// field is inline and exported but was not scanned
				errList.WriteError(fmt.Sprintf("field %s.%s is declared but not found\n", goPath, ident.Name))
			}
			continue
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

		newInfo := &FieldInfo{
			JsonName: jsonName,
			GoPath:   goPath + "." + goName,
			Doc:      docs,
			JsonType: goTypeToJson(structObjs, ident.Name),
			IsArray:  isExprArray(field.Type),
		}
		if structObjs[ident.Name] != nil {
			newInfo.GoPath = goName
			processXTykFields(newInfo, structObjs, structObjs[ident.Name], newInfo.GoPath, errList)
		}

		info.Fields = append(info.Fields, newInfo)
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
			lineComment = strings.TrimLeft(lineComment, "//")
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

func goTypeToJson(globals map[string]*ast.StructType, typeName string) string {
	switch typeName {
	case "string":
		return "string"
	case "int", "uint", "int64", "uint64", "int32", "uint32", "float", "float64", "float32":
		return "number"
	case "bool":
		return "boolean"
	default:
		if _, ok := globals[typeName]; ok {
			return "object"
		}
	}
	return ""
}
