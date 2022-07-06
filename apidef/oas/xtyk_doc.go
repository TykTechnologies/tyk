package oas

//go:generate go test -run=TestExtractDocFromXTyk . -timeout 7s -v -x-tyk-dump-doc

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
)

// XTykDoc is a list of information for exported struct type info,
// starting from the root struct declaration(XTykGateway)
type XTykDoc []*StructInfo

func (x *XTykDoc) append(newInfo *StructInfo) int {
	*x = append(*x, newInfo)
	return len(*x)
}

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
	// MapKey is the map key type, if this field is a map
	MapKey string `json:"map_key,omitempty"`
	// IsArray reports if this field is an array.
	IsArray bool `json:"is_array"`
}

type FieldDocError struct {
	errs []string
}

func (err *FieldDocError) Error() string {
	return strings.Join(err.errs, "\n")
}

func (err *FieldDocError) WriteError(errMsg string) {
	err.errs = append(err.errs, errMsg)
}

func (err *FieldDocError) Empty() bool {
	return len(err.errs) == 0
}

// ExtractDocFromXTyk returns documentation associated with XTykAPIGateway struct or error.
// if err is of type *FieldDocError, documentation may not be empty.
func ExtractDocFromXTyk() (XTykDoc, error) {
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

	p := newObjParser(pkgs[requiredPkgName])
	rootStructInfo := &StructInfo{
		Name:      rootJsonName,
		structObj: p.globals[rootStructName].(*ast.StructType),
	}
	p.parse(rootJsonName, rootJsonName, rootStructInfo)

	if p.errList.Empty() {
		return p.info, nil
	}
	return p.info, p.errList
}

type objParser struct {
	info    XTykDoc
	globals map[string]ast.Expr    // exported global types
	visited map[string]*StructInfo // avoid re-visiting struct type
	pkg     *ast.Package
	errList *FieldDocError
}

func newObjParser(pkg *ast.Package) *objParser {
	p := &objParser{
		info:    XTykDoc{},
		visited: map[string]*StructInfo{},
		errList: &FieldDocError{},
		pkg:     pkg,
	}
	p.parseGlobalExpr()
	return p
}

func (p *objParser) parseGlobalExpr() {
	p.globals = map[string]ast.Expr{}
	for _, fileObj := range p.pkg.Files {
		if fileObj.Scope == nil {
			continue
		}
		for objName, obj := range fileObj.Scope.Objects {
			if decl, ok := obj.Decl.(*ast.TypeSpec); ok && ast.IsExported(objName) {
				switch obj := decl.Type.(type) {
				case *ast.StructType, *ast.ArrayType, *ast.MapType:
					p.globals[objName] = obj
				}
			}
		}
	}
}

func (p *objParser) parse(goPath, name string, structInfo *StructInfo) {
	if p.visited[name] != nil {
		return
	}
	p.visited[name] = structInfo
	p.info.append(structInfo)
	for _, field := range structInfo.structObj.Fields.List {
		ident := extractIdentFromExpr(field.Type)
		if ident == nil {
			if len(field.Names) > 0 {
				// inline fields
				ident = extractIdentFromExpr(p.globals[field.Names[0].Name])
			}
			if ident == nil {
				p.errList.WriteError(fmt.Sprintf("identifier from %s is not known\n", goPath))
				continue
			}
		}

		var goName string
		if len(field.Names) > 0 {
			goName = field.Names[0].Name
		}
		if goName == "_" {
			// ignored field.
			continue
		}

		jsonName, isInline := jsonTagFromBasicLit(field.Tag)
		if isInline {
			p.parseInlineField(goPath, ident.Name, structInfo)
			continue
		}
		if jsonName == "" && !isInline {
			// field is for internal use?
			continue
		}
		if goName == "" {
			p.errList.WriteError(fmt.Sprintf("unidentified field in %s", goPath))
			continue
		}

		docs := cleanDocs(field.Doc)
		if docs == "" {
			p.errList.WriteError(fmt.Sprintf("field %s.%s is missing documentation", goPath, goName))
		}

		fieldInfo := &FieldInfo{
			JsonName: jsonName,
			GoPath:   goPath + "." + goName,
			Doc:      docs,
			JsonType: goTypeToJson(p.globals, ident.Name),
			IsArray:  isExprArray(field.Type),
		}
		p.parseNestedObj(ident.Name, fieldInfo)
		structInfo.Fields = append(structInfo.Fields, fieldInfo)
	}
}

func (p *objParser) parseInlineField(path, name string, structInfo *StructInfo) {
	// for inline Global "struct", keep tree as it was but change the root struct
	if structObj, ok := p.globals[name].(*ast.StructType); ok {
		newInfo := p.visited[name]
		if newInfo == nil {
			newInfo = &StructInfo{structObj: structObj, Name: name}
		}
		p.parse(path, name, newInfo)
		structInfo.Fields = append(structInfo.Fields, newInfo.Fields...)
	} else {
		// field is inline and exported but was not scanned
		p.errList.WriteError(fmt.Sprintf("field %s.%s is declared but not found\n", path, name))
	}
}

func (p *objParser) parseNestedObj(name string, field *FieldInfo) {
	if p.globals[name] != nil {
		switch obj := p.globals[name].(type) {
		case *ast.StructType:
			newInfo := &StructInfo{structObj: obj, Name: name}
			p.parse(name, name, newInfo)

		case *ast.ArrayType:
			typeName := extractIdentFromExpr(obj).Name
			field.JsonType = typeName
			field.IsArray = true
			if structObj, ok := p.globals[typeName].(*ast.StructType); ok {
				newInfo := &StructInfo{structObj: structObj, Name: typeName}
				p.parse(typeName, typeName, newInfo)
			}

		case *ast.MapType:
			typeName := extractIdentFromExpr(obj).Name
			field.JsonType = typeName
			field.MapKey = extractIdentFromExpr(obj.Key).Name
			if structObj, ok := p.globals[typeName].(*ast.StructType); ok {
				newInfo := &StructInfo{structObj: structObj, Name: typeName}
				p.parse(typeName, typeName, newInfo)
			}

		}
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
		return extractIdentFromExpr(objType.X)

	case *ast.Ident:
		return objType

	case *ast.MapType:
		return extractIdentFromExpr(objType.Value)

	case *ast.ArrayType:
		return extractIdentFromExpr(objType.Elt)

	case *ast.InterfaceType:
		return ast.NewIdent("any")

	case *ast.SelectorExpr:
		return ast.NewIdent("object")
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

	if len(jsonTags) > 1 && jsonTags[1] == "inline" {
		return "", true
	}

	if jsonTags[0] == "" || jsonTags[0] == "-" {
		return "", false
	}

	return jsonTags[0], false
}

func filterXTykGoFile(fInfo os.FileInfo) bool {
	ignoreList := map[string]bool{
		"default.go":   true,
		"oasutil.go":   true,
		"oas.go":       true,
		"validator.go": true,
		"xtyk_doc.go":  true,
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
	case "any", "object":
		return typeName
	default:
		if _, ok := globals[typeName]; ok {
			return typeName
		}
	}
	return ""
}

const xTykDocMarkdownTitle = `
## TYK OAS API Object

`

func xTykDocToMarkdown(xtykDoc XTykDoc) string {

	docWriter := strings.Builder{}
	docWriter.WriteString(xTykDocMarkdownTitle)

	for _, structInfo := range xtykDoc {
		docWriter.WriteString(fmt.Sprintf("### **%s**\n\n", structInfo.Name))

		for _, field := range structInfo.Fields {
			fieldInfoToMarkdown(field, &docWriter)
		}
		docWriter.WriteByte('\n')
	}
	return docWriter.String()
}

func fieldInfoToMarkdown(field *FieldInfo, docWriter *strings.Builder) {
	docWriter.WriteString(fmt.Sprintf("- **`%s`**\n\n", field.JsonName))

	if field.JsonType != "" {
		docWriter.WriteString("  **Type: ")
		docWriter.WriteString(fmt.Sprintf("%s**\n\n", fieldTypeToMarkdown(field)))
	}

	if field.Doc != "" {
		for _, doc := range strings.Split(field.Doc, "\n") {
			if doc != "" {
				docWriter.WriteString(fmt.Sprintf("  %s\n\n", doc))
			}
		}
	}
}

func fieldTypeToMarkdown(f *FieldInfo) string {
	ext := ""
	if f.IsArray {
		ext = "[]"
	}
	if f.MapKey != "" {
		ext = fmt.Sprintf("map[%s]", f.MapKey) + ext
	}

	switch f.JsonType {
	case "boolean", "int", "float", "double", "string", "any", "object":
		return fmt.Sprintf("`%s%s`", ext, f.JsonType)
	}

	if ext != "" {
		ext = "`" + ext + "`"
	}
	// markdown link
	return fmt.Sprintf("%s[%s](#%s)", ext, f.JsonType, strings.ToLower(f.JsonType))
}
