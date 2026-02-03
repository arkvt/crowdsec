package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunCrowdsecCreatesDbClientForPusher(t *testing.T) {
	srcPath := sourcePath(t, "crowdsec.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parse crowdsec.go: %v", err)
	}

	runCrowdsec := findFuncDecl(file, "runCrowdsec")
	if runCrowdsec == nil || runCrowdsec.Body == nil {
		t.Fatal("runCrowdsec not found in crowdsec.go")
	}

	if !assignsDbClientFromNewClient(runCrowdsec.Body) {
		t.Fatalf("expected runCrowdsec to assign dbClient from database.NewClient for pusher alerts/decisions sync")
	}
}

func sourcePath(t *testing.T, filename string) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Join(filepath.Dir(current), filename)
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func assignsDbClientFromNewClient(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if !assignsIdentifier(assign.Lhs, "dbClient") {
			return true
		}
		if callsDatabaseNewClient(assign.Rhs) {
			found = true
			return false
		}
		return true
	})
	return found
}

func assignsIdentifier(exprs []ast.Expr, name string) bool {
	for _, expr := range exprs {
		ident, ok := expr.(*ast.Ident)
		if ok && ident.Name == name {
			return true
		}
	}
	return false
}

func callsDatabaseNewClient(exprs []ast.Expr) bool {
	for _, expr := range exprs {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkgIdent, ok := selector.X.(*ast.Ident)
		if !ok {
			continue
		}
		if pkgIdent.Name == "database" && selector.Sel != nil && selector.Sel.Name == "NewClient" {
			return true
		}
	}
	return false
}
