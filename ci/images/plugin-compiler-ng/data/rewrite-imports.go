package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type edit struct {
	start int
	end   int
	value string
}

type fileRewrite struct {
	path     string
	mode     os.FileMode
	contents []byte
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: rewrite-imports <old-module> <new-module> <source-root>")
		os.Exit(2)
	}

	if err := rewriteTree(os.Args[3], os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "rewrite imports: %v\n", err)
		os.Exit(1)
	}
}

func rewriteTree(root, oldModule, newModule string) error {
	var rewrites []fileRewrite
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if path != root {
				name := info.Name()
				if name == ".git" || name == "vendor" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := info.Name()
		if !info.Mode().IsRegular() || filepath.Ext(path) != ".go" ||
			strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		rewrite, err := prepareRewrite(path, info.Mode().Perm(), oldModule, newModule)
		if err != nil {
			return err
		}
		if rewrite != nil {
			rewrites = append(rewrites, *rewrite)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, rewrite := range rewrites {
		if err := writeFile(rewrite); err != nil {
			return err
		}
	}
	return nil
}

func prepareRewrite(path string, mode os.FileMode, oldModule, newModule string) (*fileRewrite, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, path, contents, parser.ImportsOnly)
	if err != nil {
		// Build-constraint and tooling files can contain syntax unsupported by
		// the target Go release. The actual go build remains authoritative.
		return nil, nil
	}

	var edits []edit
	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid import path: %w", path, err)
		}
		if importPath != oldModule && !strings.HasPrefix(importPath, oldModule+"/") {
			continue
		}

		start := files.Position(spec.Path.Pos()).Offset
		end := files.Position(spec.Path.End()).Offset
		edits = append(edits, edit{
			start: start,
			end:   end,
			value: strconv.Quote(newModule + strings.TrimPrefix(importPath, oldModule)),
		})
	}
	if len(edits) == 0 {
		return nil, nil
	}

	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, change := range edits {
		updated := make([]byte, 0, len(contents)-change.end+change.start+len(change.value))
		updated = append(updated, contents[:change.start]...)
		updated = append(updated, change.value...)
		updated = append(updated, contents[change.end:]...)
		contents = updated
	}

	return &fileRewrite{path: path, mode: mode, contents: contents}, nil
}

func writeFile(rewrite fileRewrite) error {
	tmp, err := os.CreateTemp(filepath.Dir(rewrite.path), ".tyk-rewrite-imports-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err = tmp.Write(rewrite.contents); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(rewrite.mode); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, rewrite.path)
}
