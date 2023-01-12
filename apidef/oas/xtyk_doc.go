package oas

//go:generate go test -run=TestExtractDocFromXTyk . -count 1 -v -timeout 7s -x-tyk-dump-doc

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
// starting from the root struct declaration(XTykGateway).
type XTykDoc []*StructInfo

func (x *XTykDoc) append(newInfo *StructInfo) int {
	*x = append(*x, newInfo)
	return len(*x)
}

// StructInfo holds ast field information for the docs generator.
type StructInfo struct {
	// Name is struct go name.
	Name string

	// Fields holds information of the fields, if this object is a struct.
	Fields []*FieldInfo `json:"fields,omitempty"`

	// fileSet holds a token.FileSet, used to resolve symbols to file:line
	fileSet *token.FileSet

	// structObj is the raw ast.StructType value, private.
	structObj *ast.StructType
}

// FieldInfo holds details about a field.
type FieldInfo struct {
	// Doc is field docs. comments that are not part of docs are excluded.
	Doc string `json:"doc"`

	// JSONName is the corresponding json name of the field.
	JSONName string `json:"json_name"`

	// JSONType valid json type if it was found
	JSONType string `json:"json_type"`

	// GoPath is the go path of this field starting from root object
	GoPath string `json:"go_path"`

	// MapKey is the map key type, if this field is a map
	MapKey string `json:"map_key,omitempty"`

	// IsArray reports if this field is an array.
	IsArray bool `json:"is_array"`

	// fileSet holds a token.FileSet, used to resolve symbols to file:line
	fileSet *token.FileSet
}

// FieldDocError holds a list of errors.
type FieldDocError struct {
	errs []string
}

// Error implements the error interface.
func (err *FieldDocError) Error() string {
	return strings.Join(err.errs, "\n")
}

// WriteError appends an error message to the error list.
func (err *FieldDocError) WriteError(errMsg string) {
	err.errs = append(err.errs, errMsg)
}

// Empty returns true if there are no errors in the list.
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
		rootJSONName    = "x-tyk-gateway"
		requiredPkgName = "oas"
	)
	if _, ok = pkgs[requiredPkgName]; !ok {
		return nil, fmt.Errorf("required package %s", requiredPkgName)
	}

	p := newObjParser(pkgs[requiredPkgName])
	rootStructInfo := &StructInfo{
		Name:      rootJSONName,
		fileSet:   fileSet,
		structObj: p.globals[rootStructName].(*ast.StructType),
	}
	p.parse(rootJSONName, rootJSONName, rootStructInfo)

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
		pos := structInfo.fileSet.Position(field.Pos())
		filePos := path.Base(pos.String())

		ident := extractIdentFromExpr(field.Type)
		if ident == nil {
			if len(field.Names) > 0 {
				// inline fields
				ident = extractIdentFromExpr(p.globals[field.Names[0].Name])
			}
			if ident == nil {
				p.errList.WriteError(fmt.Sprintf("[%s] identifier from %s is not known\n", filePos, goPath))
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
			p.errList.WriteError(fmt.Sprintf("[%s] unidentified field in %s", filePos, goPath))
			continue
		}

		docs := cleanDocs(field.Doc)
		if docs == "" {
			p.errList.WriteError(fmt.Sprintf("[%s] %s.%s is missing documentation", filePos, goPath, goName))
		}

		if len(docs) <= len(goName) || !strings.HasPrefix(docs, goName+" ") {
			p.errList.WriteError(fmt.Sprintf("[%s] %s.%s has invalid documentation, should start with field name", filePos, goPath, goName))
		}

		fieldInfo := &FieldInfo{
			JSONName: jsonName,
			GoPath:   goPath + "." + goName,
			Doc:      docs,
			JSONType: goTypeToJSON(p.globals, ident.Name),
			IsArray:  isExprArray(field.Type),
			fileSet:  structInfo.fileSet,
		}
		p.parseNestedObj(ident.Name, fieldInfo)
		structInfo.Fields = append(structInfo.Fields, fieldInfo)
	}
}

func (p *objParser) parseInlineField(pathName, name string, structInfo *StructInfo) {
	// for inline Global "struct", keep tree as it was but change the root struct
	if structObj, ok := p.globals[name].(*ast.StructType); ok {
		newInfo := p.visited[name]
		if newInfo == nil {
			newInfo = &StructInfo{
				structObj: structObj,
				fileSet:   structInfo.fileSet,
				Name:      name,
			}
		}
		p.parse(pathName, name, newInfo)
		structInfo.Fields = append(structInfo.Fields, newInfo.Fields...)
	} else {
		// field is inline and exported but was not scanned
		p.errList.WriteError(fmt.Sprintf("field %s.%s is declared but not found\n", pathName, name))
	}
}

func (p *objParser) parseNestedObj(name string, field *FieldInfo) {
	if p.globals[name] != nil {
		switch obj := p.globals[name].(type) {
		case *ast.StructType:
			newInfo := &StructInfo{
				structObj: obj,
				fileSet:   field.fileSet,
				Name:      name,
			}
			p.parse(name, name, newInfo)

		case *ast.ArrayType:
			typeName := extractIdentFromExpr(obj).Name
			field.JSONType = typeName
			field.IsArray = true
			if structObj, ok := p.globals[typeName].(*ast.StructType); ok {
				newInfo := &StructInfo{
					structObj: structObj,
					fileSet:   field.fileSet,
					Name:      typeName,
				}
				p.parse(typeName, typeName, newInfo)
			}

		case *ast.MapType:
			typeName := extractIdentFromExpr(obj).Name
			field.JSONType = typeName
			field.MapKey = extractIdentFromExpr(obj.Key).Name
			if structObj, ok := p.globals[typeName].(*ast.StructType); ok {
				newInfo := &StructInfo{
					structObj: structObj,
					fileSet:   field.fileSet,
					Name:      typeName,
				}
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

		var (
			codeBlock      bool
			openBulletList bool
			lastCh         string
		)

		for _, lineComment := range strings.Split(docText, "\n") {
			lineComment = strings.TrimLeft(lineComment, "/")
			lineComment = strings.TrimLeft(lineComment, "/*")
			lineComment = strings.TrimLeft(lineComment, "*\\")

			if !codeBlock {
				lineComment = strings.TrimSpace(lineComment)
			}

			// Handle codeblock leading/trailing space
			if lineComment == "```" {
				codeBlock = !codeBlock
				s.WriteByte('\n')
				if codeBlock {
					s.WriteByte('\n')
					s.WriteString(lineComment)
				} else {
					s.WriteString(lineComment)
					s.WriteByte('\n')
				}
				s.WriteByte('\n')
				continue
			}

			// Handle bullet lists formatting
			if lineComment != "" && lineComment[0] == '-' {
				if !openBulletList {
					s.WriteString("\n")
				}
				s.WriteString(lineComment + "\n")
				openBulletList = true
				continue
			}

			if openBulletList {
				openBulletList = false
				s.WriteString("\n")
			}

			// Prepend empty line if line starts with `Tyk native API definition`
			if strings.HasPrefix(lineComment, "Tyk native API definition") {
				s.WriteString("\n")
			}

			// Append dot after Tyk native API definition, consistency.
			if lineComment == "" && lastCh == "`" {
				s.WriteString(".\n")
				lastCh = ""
				continue
			}

			if lineComment != "" {
				s.WriteString(lineComment)

				// Each codeblock line needs a trailing \n
				if codeBlock {
					s.WriteByte('\n')
					continue
				}

				// Group other text as sentences with trailing dot.
				length := len(lineComment)
				lastCh = lineComment[length-1 : length]

				// Line ends with code block, next line determines
				// which trailing space goes after
				if lastCh == "`" {
					continue
				}

				// Group sentences into individual lines in markdown
				// or join them together with a space if split.
				if lastCh == "." || lastCh == ":" {
					s.WriteByte('\n')
					continue
				}

				s.WriteByte(' ')
				continue
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
	_, ok := expr.(*ast.ArrayType)
	return ok
}

func jsonTagFromBasicLit(tag *ast.BasicLit) (name string, isInline bool) {
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

func goTypeToJSON(globals map[string]ast.Expr, typeName string) string {
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
	docWriter.WriteString(fmt.Sprintf("**Field: `%s` (%s)**\n\n", field.JSONName, fieldTypeToMarkdown(field)))
	docWriter.WriteString(strings.TrimSpace(field.Doc) + "\n\n")
}

func fieldTypeToMarkdown(f *FieldInfo) string {
	ext := ""
	if f.IsArray {
		ext = "[]"
	}
	if f.MapKey != "" {
		ext = fmt.Sprintf("map[%s]", f.MapKey) + ext
	}

	switch f.JSONType {
	case "boolean", "int", "float", "double", "string", "any", "object":
		return fmt.Sprintf("`%s%s`", ext, f.JSONType)
	}

	if ext != "" {
		ext = "`" + ext + "`"
	}
	// markdown link
	return fmt.Sprintf("%s[%s](#%s)", ext, f.JSONType, strings.ToLower(f.JSONType))
}
