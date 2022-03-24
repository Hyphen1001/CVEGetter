package treesitter

import (
	"context"
	"edu.buaa.soft/CVEGetter/entity"
	sitter "github.com/smacker/go-tree-sitter"
)

type SitterParser struct {
	RootNode  *sitter.Node
	Code      []byte
	FuncArray []*entity.FuncContentArray
}

func NewSitterParser(code []byte, codeType *sitter.Language, suffix string) *SitterParser {
	parser := sitter.NewParser()
	parser.SetLanguage(codeType)
	tree, _ := parser.ParseCtx(context.Background(), nil, code)
	rootNode := tree.RootNode()
	return &SitterParser{
		RootNode:  rootNode,
		Code:      code,
		FuncArray: GetFuncArrayImpl(rootNode, suffix),
	}
}

type ContentDTO struct {
	Contents       string `json:"Contents"`
	TreeSitterType string `json:"tree_sitter_type"`
}

func (s *SitterParser) ParseLineToFunc(startLine, endLine int) []*ContentDTO {
	ret := []*ContentDTO{}
	startIndex, endIndex := s.parseLineToIndex(startLine), s.parseLineToIndex(endLine)
	for _, array := range s.FuncArray {
		if (array.Bound[1] >= startIndex && array.Bound[0] <= startIndex) ||
			(array.Bound[0] <= endIndex && array.Bound[1] >= endIndex) ||
			(array.Bound[0] >= startIndex && array.Bound[1] <= endIndex) {
			ret = append(ret,
				&ContentDTO{
					Contents:       string(s.Code[array.Bound[0] : array.Bound[1]+1]),
					TreeSitterType: array.TreeSitterType,
				},
			)
		}
	}
	return ret
}

func (s *SitterParser) parseLineToIndex(line int) uint64 {
	lineIndex := 1
	for i := uint64(0); i < uint64(len(s.Code)); i++ {
		if lineIndex == line {
			return i
		}
		if s.Code[i] == '\n' && (i == 0 || s.Code[i-1] != '\\') {
			lineIndex++
		}
	}
	return 0
}
