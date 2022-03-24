package treesitter_test

import (
	"fmt"
	"github.com/smacker/go-tree-sitter/cpp"
	"os"
	"testing"

	"edu.buaa.soft/CVEGetter/utils/treesitter"
)

func TestNewSitterParser(t *testing.T) {
	code, err := os.ReadFile("./test.txt")
	if err != nil {
		panic(err)
	}
	sitterParser := treesitter.NewSitterParser(code, cpp.GetLanguage(), "cpp")
	ret := sitterParser.ParseLineToFunc(636, 641)
	fmt.Println(len(ret))
	for _, s := range ret {
		fmt.Println(s.TreeSitterType)
		fmt.Println(s.Contents)
		fmt.Println("===============")
	}
}
