package ofauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestExportedIdentifiersHaveDocComments fails when an exported top-level
// identifier (type, func, method on an exported type, const, var) in the
// package or in ofauthtest has no doc comment. Generated files included: the
// docs on pkg.go.dev come from these comments.
func TestExportedIdentifiersHaveDocComments(t *testing.T) {
	for _, dir := range []string{".", "ofauthtest"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(info fs.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, pkg := range pkgs {
			if pkg.Name == "main" {
				continue
			}
			for _, file := range pkg.Files {
				for _, missing := range undocumented(file) {
					t.Errorf("%s: exported %s has no doc comment", fset.Position(missing.Pos()), missing.Name)
				}
			}
		}
	}
}

func undocumented(file *ast.File) []*ast.Ident {
	var out []*ast.Ident
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if !d.Name.IsExported() || d.Doc != nil {
				continue
			}
			if d.Recv != nil && !exportedReceiver(d.Recv.List[0].Type) {
				continue
			}
			out = append(out, d.Name)
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() && s.Doc == nil && d.Doc == nil {
						out = append(out, s.Name)
					}
				case *ast.ValueSpec:
					if s.Doc != nil || d.Doc != nil {
						continue
					}
					for _, name := range s.Names {
						if name.IsExported() {
							out = append(out, name)
						}
					}
				}
			}
		}
	}
	return out
}

func exportedReceiver(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return exportedReceiver(e.X)
	case *ast.IndexExpr:
		return exportedReceiver(e.X)
	case *ast.IndexListExpr:
		return exportedReceiver(e.X)
	case *ast.Ident:
		return e.IsExported()
	}
	return false
}
