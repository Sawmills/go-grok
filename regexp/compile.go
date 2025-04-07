package regexp

import (
	"github.com/wasilibs/go-re2"
)

type Matcher interface {
	MatchString(s string) bool
	FindAllString(s string, n int) []string
	ReplaceAllString(s string, replacement string) string
	SubexpNames() []string
	FindStringSubmatch(s string) []string
	FindAllStringSubmatchIndex(s string, n int) [][]int
	ExpandString(dst []byte, template string, src string, match []int) []byte
	FindAllStringSubmatch(s string, n int) [][]string
	Match(b []byte) bool
}

func Compile(pattern string) (Matcher, error) {
	return re2.Compile(pattern)
}

func MustCompile(pattern string) Matcher {
	return re2.MustCompile(pattern)
}
