package structs

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
)

const lintDocs = false

// Extract package structs
func Extract(filepath string, ignoreFiles ...string) (StructList, error) {
	ignoreList := make(map[string]bool)
	for _, file := range ignoreFiles {
		ignoreList[file] = true
	}

	// filter skips explicitly ignored files, and tests files
	filter := func(fInfo os.FileInfo) bool {
		return !(ignoreList[fInfo.Name()] || strings.HasSuffix(fInfo.Name(), "_test.go"))
	}

	fileSet := token.NewFileSet()
	pkgs, err := parser.ParseDir(fileSet, path.Dir(filepath), filter, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	if len(pkgs) != 1 {
		return nil, fmt.Errorf("expecting single go package, got %d", len(pkgs))
	}

	requiredPkgName := func() string {
		// Get first package name
		var pkgName string
		for pkgName, _ = range pkgs {
			break
		}
		return pkgName
	}()

	if _, ok := pkgs[requiredPkgName]; !ok {
		return nil, fmt.Errorf("required package %q", requiredPkgName)
	}

	p := newObjParser(fileSet, pkgs[requiredPkgName])
	p.parseGlobalStructs()

	sort.Stable(p.info)

	if p.errList.Empty() {
		return p.info, nil
	}
	return p.info, p.errList
}

type objParser struct {
	fileset *token.FileSet

	info    StructList
	globals map[string]ast.Expr    // exported global types
	visited map[string]*StructInfo // avoid re-visiting struct type
	pkg     *ast.Package
	errList *FieldDocError
}

func newObjParser(fileset *token.FileSet, pkg *ast.Package) *objParser {
	p := &objParser{
		fileset: fileset,
		info:    StructList{},
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
				switch objType := decl.Type.(type) {
				case *ast.StructType, *ast.ArrayType, *ast.MapType:
					p.globals[objName] = objType
				}
			}
		}
	}
}

func (p *objParser) parseGlobalStructs() {
	for rootName, g := range p.globals {
		switch obj := g.(type) {
		case *ast.StructType:
			rootStructInfo := &StructInfo{
				Name:      rootName,
				fileSet:   p.fileset,
				structObj: obj, // p.globals[rootName].(*ast.StructType),
			}
			p.parse(rootName, rootName, rootStructInfo)
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

		var goName string
		if len(field.Names) > 0 {
			goName = field.Names[0].Name
		}

		// ignored field.
		if goName == "_" {
			continue
		}
		if goName == "" {
			p.errList.WriteError(fmt.Sprintf("[%s] unidentified field in %s", filePos, goPath))
			continue
		}

		// fmt.Println("goName", goName)

		ident := extractIdentFromExpr(field.Type)
		if ident == nil {
			if len(field.Names) > 0 {
				// inline fields
				ident = extractIdentFromExpr(p.globals[goName])
			}
		}
		if ident == nil {
			ident = ast.NewIdent("any")
		}

		tagValue := ""
		if field.Tag != nil {
			tagValue = string(field.Tag.Value)
			tagValue = strings.Trim(tagValue, "`")
		}

		jsonName := jsonTag(tagValue)
		if jsonName == "" {
			// fields without json tag encode to field name
			jsonName = goName
		}

		docs := cleanDocs(field.Doc)

		if lintDocs {
			if docs == "" {
				p.errList.WriteError(fmt.Sprintf("[%s] %s.%s is missing documentation", filePos, goPath, goName))
			}

			if len(docs) <= len(goName) || !strings.HasPrefix(docs, goName+" ") {
				p.errList.WriteError(fmt.Sprintf("[%s] %s.%s has invalid documentation, should start with field name", filePos, goPath, goName))
			}
		}

		fieldInfo := &FieldInfo{
			Doc: docs,

			GoName: goName,
			GoPath: goPath + "." + goName,
			GoType: ident.String(),

			Tag: tagValue,

			JSONName: jsonName,

			IsArray: isExprArray(field.Type),

			fileSet: structInfo.fileSet,
		}
		// p.parseNestedObj(ident.Name, fieldInfo)

		structInfo.Fields = append(structInfo.Fields, fieldInfo)
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
			field.GoType = "[]" + typeName
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
			field.MapKey = extractIdentFromExpr(obj.Key).Name
			field.GoType = fmt.Sprintf("map[%s]%s", typeName, field.MapKey)

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

			// Prepend empty line if line starts with `Tyk classic API definition`
			if strings.HasPrefix(lineComment, "Tyk classic API definition") {
				s.WriteString("\n")
			}

			// Append dot after Tyk classic API definition, consistency.
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

func jsonTag(tag string) string {
	return reflect.StructTag(tag).Get("json")
}
