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

type legacyMatcher struct{}

func (legacyMatcher) MatchString(string) bool                           { return false }
func (legacyMatcher) FindAllString(string, int) []string                { return nil }
func (legacyMatcher) ReplaceAllString(string, string) string            { return "" }
func (legacyMatcher) SubexpNames() []string                             { return nil }
func (legacyMatcher) FindStringSubmatch(string) []string                { return nil }
func (legacyMatcher) FindAllStringSubmatchIndex(string, int) [][]int    { return nil }
func (legacyMatcher) ExpandString([]byte, string, string, []int) []byte { return nil }
func (legacyMatcher) FindAllStringSubmatch(string, int) [][]string      { return nil }
func (legacyMatcher) Match([]byte) bool                                 { return false }
func (legacyMatcher) Split(string, int) []string                        { return nil }

var _ Matcher = legacyMatcher{}
