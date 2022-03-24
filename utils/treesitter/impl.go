package treesitter

import (
	"edu.buaa.soft/CVEGetter/entity"
	sitter "github.com/smacker/go-tree-sitter"
)

const (
	typePreprocInclude     = "preproc_include"
	typeFunctionDefinition = "function_definition"
	typePreprocDef         = "preproc_def"
	typeStructSpecifier    = "struct_specifier"

	typeImportDeclaration = "import_declaration"
	typeMethodDeclaration = "method_declaration"

	//python特有
	typeImportFromStatement   = "import_from_statement"
	typeFutureImportStatement = "future_import_statement"
	typeImportStatement       = "import_statement "

	//go特有
	typeTypeDeclaration     = "type_declaration"
	typeConstDeclaration    = "const_declaration"
	typeVarDeclaration      = "var_declaration"
	typeFunctionDeclaration = "function_declaration"
)

func GetFuncArrayImpl(rootNode *sitter.Node, suffix string) []*entity.FuncContentArray {
	funcContentArray := []*entity.FuncContentArray{}
	dfsAST := func(node *sitter.Node) {}
	dfsAST = func(node *sitter.Node) {
		if getAimBySuffix(suffix, node.Type()) {
			funcContentArray = append(funcContentArray,
				&entity.FuncContentArray{
					Bound:          [2]uint64{uint64(node.StartByte()), uint64(node.EndByte())},
					TreeSitterType: node.Type(),
				},
			)
			if suffix == "go" {
				return
			}
		}
		if node.NamedChildCount() == 0 {
			return
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			dfsAST(node.NamedChild(i))
		}
	}

	dfsAST(rootNode)
	return funcContentArray
}

func getAimBySuffix(suffix string, nodeType string) bool {
	switch suffix {
	case "cpp":
		return nodeType == typeStructSpecifier || nodeType == typePreprocDef ||
			nodeType == typeFunctionDefinition || nodeType == typePreprocInclude
	case "c":
		return nodeType == typeStructSpecifier || nodeType == typePreprocDef ||
			nodeType == typeFunctionDefinition || nodeType == typePreprocInclude
	case "java":
		return nodeType == typeImportDeclaration || nodeType == typeMethodDeclaration
	case "py":
		return nodeType == typeImportStatement || nodeType == typeFunctionDefinition ||
			nodeType == typeFutureImportStatement || nodeType == typeImportFromStatement
	case "go":
		return nodeType == typeMethodDeclaration || nodeType == typeFunctionDeclaration ||
			nodeType == typeTypeDeclaration || nodeType == typeConstDeclaration ||
			nodeType == typeVarDeclaration
	default:
		return false
	}
}
