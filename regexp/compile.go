// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
	Split(s string, n int) []string
}

func Compile(pattern string) (Matcher, error) {
	return re2.Compile(pattern)
}

func MustCompile(pattern string) Matcher {
	return re2.MustCompile(pattern)
}
