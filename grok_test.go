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

package grok_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-grok"
)

func TestMatch(t *testing.T) {
	testCases := []struct {
		Name          string
		Patterns      map[string]string
		Pattern       string
		Text          string
		ExpectedMatch bool
	}{
		{"no pattern, no text", nil, ``, ``, true},
		{"no pattern, some text", nil, ``, `some text`, true},
		{"regex match", nil, `foo.*`, `seafood`, true},
		{"regex no match", nil, `bar.*`, `seafood`, false},

		// test from golang regex library
		{"Go regex 1", nil, `a+`, "baaab", true},
		{"Go regex 2", nil, "abcd..", "abcdef", true},
		{"Go regex 3", nil, `a`, "a", true},
		{"Go regex 4", nil, `x`, "y", false},
		{"Go regex 5", nil, `b`, "abc", true},
		{"Go regex 6", nil, `.`, "a", true},
		{"Go regex 7", nil, `.*`, "abcdef", true},
		{"Go regex 8", nil, `^`, "abcde", true},
		{"Go regex 9", nil, `$`, "abcde", true},
		{"Go regex 10", nil, `^abcd$`, "abcd", true},
		{"Go regex 11", nil, `^bcd'`, "abcdef", false},
		{"Go regex 12", nil, `^abcd$`, "abcde", false},
		{"Go regex 13", nil, `a+`, "baaab", true},
		{"Go regex 14", nil, `a*`, "baaab", true},
		{"Go regex 15", nil, `[a-z]+`, "abcd", true},
		{"Go regex 16", nil, `[^a-z]+`, "ab1234cd", true},
		{"Go regex 17", nil, `[a\-\]z]+`, "az]-bcz", true},
		{"Go regex 18", nil, `[^\n]+`, "abcd\n", true},
		{"Go regex 19", nil, `[日本語]+`, "日本語日本語", true},
		{"Go regex 20", nil, `日本語+`, "日本語", true},
		{"Go regex 21", nil, `日本語+`, "日本語語語語", true},
		{"Go regex 22", nil, `()`, "", true},
		{"Go regex 23", nil, `(a)`, "a", true},
		{"Go regex 24", nil, `(.)(.)`, "日a", true},
		{"Go regex 25", nil, `(.*)`, "", true},
		{"Go regex 26", nil, `(.*)`, "abcd", true},
		{"Go regex 27", nil, `(..)(..)`, "abcd", true},
		{"Go regex 28", nil, `(([^xyz]*)(d))`, "abcd", true},
		{"Go regex 29", nil, `((a|b|c)*(d))`, "abcd", true},
		{"Go regex 30", nil, `(((a|b|c)*)(d))`, "abcd", true},
		{"Go regex 31", nil, `\a\f\n\r\t\v`, "\a\f\n\r\t\v", true},
		{"Go regex 32", nil, `[\a\f\n\r\t\v]+`, "\a\f\n\r\t\v", true},

		// RE2 tests
		{"Go regex 33", nil, `[^\S\s]`, "abcd", false},
		{"Go regex 34", nil, `[^\S[:space:]]`, "abcd", false},
		{"Go regex 35", nil, `[^\D\d]`, "abcd", false},
		{"Go regex 36", nil, `[^\D[:digit:]]`, "abcd", false},
		{"Go regex 37", nil, `(?i)\W`, "x", false},
		{"Go regex 38", nil, `(?i)\W`, "k", false},
		{"Go regex 39", nil, `(?i)\W`, "s", false},

		// simple pattern definitions
		{"Go regex 1 with pattern", map[string]string{"PATTERN": "a+"}, `%{PATTERN}`, "baaab", true},

		{"Go regex 2 with pattern", map[string]string{"PATTERN": "abcd.."}, `%{PATTERN}`, "abcdef", true},
		{"Go regex 3 with pattern", map[string]string{"PATTERN": `a`}, `%{PATTERN}`, "a", true},
		{"Go regex 4 with pattern", map[string]string{"PATTERN": `x`}, `%{PATTERN}`, "y", false},
		{"Go regex 5 with pattern", map[string]string{"PATTERN": `b`}, `%{PATTERN}`, "abc", true},
		{"Go regex 6 with pattern", map[string]string{"PATTERN": `.`}, `%{PATTERN}`, "a", true},
		{"Go regex 7 with pattern", map[string]string{"PATTERN": `.*`}, `%{PATTERN}`, "abcdef", true},
		{"Go regex 8 with pattern", map[string]string{"PATTERN": `^`}, `%{PATTERN}`, "abcde", true},
		{"Go regex 9 with pattern", map[string]string{"PATTERN": `$`}, `%{PATTERN}`, "abcde", true},
		{"Go regex 10 with pattern", map[string]string{"PATTERN": `^abcd$`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 11 with pattern", map[string]string{"PATTERN": `^bcd'`}, `%{PATTERN}`, "abcdef", false},
		{"Go regex 12 with pattern", map[string]string{"PATTERN": `^abcd$`}, `%{PATTERN}`, "abcde", false},
		{"Go regex 13 with pattern", map[string]string{"PATTERN": `a+`}, `%{PATTERN}`, "baaab", true},
		{"Go regex 14 with pattern", map[string]string{"PATTERN": `a*`}, `%{PATTERN}`, "baaab", true},
		{"Go regex 15 with pattern", map[string]string{"PATTERN": `[a-z]+`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 16 with pattern", map[string]string{"PATTERN": `[^a-z]+`}, `%{PATTERN}`, "ab1234cd", true},
		{"Go regex 17 with pattern", map[string]string{"PATTERN": `[a\-\]z]+`}, `%{PATTERN}`, "az]-bcz", true},
		{"Go regex 18 with pattern", map[string]string{"PATTERN": `[^\n]+`}, `%{PATTERN}`, "abcd\n", true},
		{"Go regex 19 with pattern", map[string]string{"PATTERN": `[日本語]+`}, `%{PATTERN}`, "日本語日本語", true},
		{"Go regex 20 with pattern", map[string]string{"PATTERN": `日本語+`}, `%{PATTERN}`, "日本語", true},
		{"Go regex 21 with pattern", map[string]string{"PATTERN": `日本語+`}, `%{PATTERN}`, "日本語語語語", true},
		{"Go regex 22 with pattern", map[string]string{"PATTERN": `()`}, `%{PATTERN}`, "", true},
		{"Go regex 23 with pattern", map[string]string{"PATTERN": `(a)`}, `%{PATTERN}`, "a", true},
		{"Go regex 24 with pattern", map[string]string{"PATTERN": `(.)(.)`}, `%{PATTERN}`, "日a", true},
		{"Go regex 25 with pattern", map[string]string{"PATTERN": `(.*)`}, `%{PATTERN}`, "", true},
		{"Go regex 26 with pattern", map[string]string{"PATTERN": `(.*)`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 27 with pattern", map[string]string{"PATTERN": `(..)(..)`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 28 with pattern", map[string]string{"PATTERN": `(([^xyz]*)(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 29 with pattern", map[string]string{"PATTERN": `((a|b|c)*(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 30 with pattern", map[string]string{"PATTERN": `(((a|b|c)*)(d))`}, `%{PATTERN}`, "abcd", true},
		{"Go regex 31 with pattern", map[string]string{"PATTERN": `\a\f\n\r\t\v`}, `%{PATTERN}`, "\a\f\n\r\t\v", true},
		{"Go regex 32 with pattern", map[string]string{"PATTERN": `[\a\f\n\r\t\v]+`}, `%{PATTERN}`, "\a\f\n\r\t\v", true},

		// nested patterns
		{"hostname defined by nested patterns", map[string]string{
			"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
			"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
			"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			"NUMBER":             `\d+`,
			"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
			"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
		}, "%{NGINX_HOST}", "127.0.0.1:1234", true},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithoutDefaultPatterns()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, true))

			isMatch := g.MatchString(tt.Text)
			require.Equal(t, tt.ExpectedMatch, isMatch)
		})
	}
}

func TestParse(t *testing.T) {
	testCases := []struct {
		Name              string
		Patterns          map[string]string
		Pattern           string
		Text              string
		ExpectedMatches   map[string]string
		NamedCapturesOnly bool
	}{
		{
			"hostname defined by nested patterns",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"NUMBER":             `\d+`,
				"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
				"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
			},
			true,
		},

		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"IP":                 `(?:\[%{IPV6}\]|%{IPV6}|%{IPV4})`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"NUMBER":             `\d+`,
				"IPV6":               `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`,
				"IPV4":               `\b(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\b`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithoutDefaultPatterns()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))
			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestParseWithDefaultPatterns(t *testing.T) {
	testCases := []struct {
		Name                 string
		Patterns             map[string]string
		Pattern              string
		Text                 string
		ExpectedMatches      map[string]string
		ExpectedTypedMatches map[string]interface{}
		NamedCapturesOnly    bool
	}{
		{
			"hostname defined by nested patterns",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
			},
			nil,
			true,
		},

		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]string{
				"destination.ip":   "127.0.0.1",
				"destination.port": "1234",
				"BASE10NUM":        "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			nil,
			false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.New()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestTypedParseWithDefaultPatterns(t *testing.T) {
	testCases := []struct {
		Name                 string
		Patterns             map[string]string
		Pattern              string
		Text                 string
		ExpectedTypedMatches map[string]interface{}
		NamedCapturesOnly    bool
	}{
		{
			"hostname defined by nested patterns, allow unnamed",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
			},
			"%{NGINX_HOST}",
			"127.0.0.1:1234",
			map[string]interface{}{
				"destination.ip":   "127.0.0.1",
				"destination.port": float64(1234),
				"BASE10NUM":        "1234",
				"NGINX_HOST":       "127.0.0.1:1234",
				"IPV4":             "127.0.0.1",
			},
			false,
		},

		{
			"hostname defined by nested patterns, typed port",
			map[string]string{
				"NGINX_HOST":         `(?:%{IP:destination.ip}|%{NGINX_NOTSEPARATOR:destination.domain})(:%{NUMBER:destination.port:int})?`,
				"NGINX_NOTSEPARATOR": `"[^\t ,:]+"`,
				"BOOL":               "true|false",
			},
			"%{NGINX_HOST} %{BOOL:destination.boolean:boolean}",
			"127.0.0.1:1234 true",
			map[string]interface{}{
				"destination.ip":      "127.0.0.1",
				"destination.port":    1234,
				"destination.boolean": true,
			},
			true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.New()
			g.AddPatterns(tt.Patterns)

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseTypedString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedTypedMatches), len(res))

			for k, v := range tt.ExpectedTypedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}

func TestDefaultPatterns(t *testing.T) {
	testCases := map[string][]string{
		"WORD":     {"hello", "world123", "test_data"},
		"NOTSPACE": {"example", "text-with-dashes", "12345"},
		"SPACE":    {" ", "\t", "  "},

		// types
		"INT":          {"123", "-456", "+789"},
		"NUMBER":       {"123", "456.789", "-0.123"},
		"BOOL":         {"true", "false", "true"},
		"BASE10NUM":    {"123", "-123.456", "0.789"},
		"BASE16NUM":    {"1a2b", "0x1A2B", "-0x1a2b3c"},
		"BASE16FLOAT":  {"0x1.a2b3", "-0x1A2B3C.D", "0x123.abc"},
		"POSINT":       {"123", "456", "789"},
		"NONNEGINT":    {"0", "123", "456"},
		"GREEDYDATA":   {"anything goes", "literally anything", "123 #@!"},
		"QUOTEDSTRING": {"\"This is a quote\"", "'single quoted'"},
		"UUID":         {"123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174001", "123e4567-e89b-12d3-a456-426614174002"},
		"URN":          {"urn:isbn:0451450523", "urn:ietf:rfc:2648", "urn:mpeg:mpeg7:schema:2001"},

		// network
		"IP":             {"192.168.1.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "172.16.254.1"},
		"IPV6":           {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "fe80::1ff:fe23:4567:890a"},
		"IPV4":           {"192.168.1.1", "10.0.0.1", "172.16.254.1"},
		"IPORHOST":       {"example.com", "192.168.1.1", "fe80::1ff:fe23:4567:890a"},
		"HOSTNAME":       {"example.com", "sub.domain.co.uk", "localhost"},
		"EMAILLOCALPART": {"john.doe", "alice123", "bob-smith"},
		"EMAILADDRESS":   {"john.doe@example.com", "alice123@domain.co.uk", "bob-smith@localhost"},
		"USERNAME":       {"user1", "john.doe", "alice_123"},
		"USER":           {"user1", "john.doe", "alice_123"},
		"MAC":            {"00:1A:2B:3C:4D:5E", "001A.2B3C.4D5E", "00-1A-2B-3C-4D-5E"},
		"CISCOMAC":       {"001A.2B3C.4D5E", "001B.2C3D.4E5F", "001C.2D3E.4F5A"},
		"WINDOWSMAC":     {"00-1A-2B-3C-4D-5E", "00-1B-2C-3D-4E-5F", "00-1C-2D-3E-4F-5A"},
		"COMMONMAC":      {"00:1A:2B:3C:4D:5E", "00:1B:2C:3D:4E:5F", "00:1C:2D:3E:4F:5A"},
		"HOSTPORT":       {"example.com:80", "192.168.1.1:8080"},

		// paths
		"UNIXPATH":     {"/home/user", "/var/log/syslog", "/tmp/abc_123"},
		"TTY":          {"/dev/pts/1", "/dev/tty0", "/dev/ttyS0"},
		"WINPATH":      {"C:\\Program Files\\App", "D:\\Work\\project\\file.txt", "E:\\New Folder\\test"},
		"URIPROTO":     {"http", "https", "ftp"},
		"URIHOST":      {"example.com", "192.168.1.1:8080"},
		"URIPATH":      {"/path/to/resource", "/another/path", "/root"},
		"URIQUERY":     {"key=value", "name=John&Doe", "search=query&active=true"},
		"URIPARAM":     {"?key=value", "?name=John&Doe", "?search=query&active=true"},
		"URIPATHPARAM": {"/path?query=1", "/resource?name=John", "/folder/path?valid=true"},
		"URI":          {"http://user:password@example.com:80/path?query=string", "https://example.com", "ftp://192.168.1.1/upload"},
		"PATH":         {"/home/user/documents", "C:\\Windows\\system32", "/var/log/syslog"},

		// dates
		"MONTH": {"January", "Feb", "March", "Apr", "May", "Jun", "Jul", "August", "September", "October", "Nov", "December"},

		// Months: January, Feb, 3, 03, 12, December "MONTH": `\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y|i)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b`,
		"MONTHNUM": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"},

		// Days Monday, Tue, Thu, etc
		"DAY": {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"},

		// Years?
		"YEAR":   {"1999", "2000", "2021"},
		"HOUR":   {"00", "12", "23"},
		"MINUTE": {"00", "30", "59"},

		// '60' is a leap second in most time standards and thus is valid.
		"SECOND": {"00", "30", "60"},
		"TIME":   {"14:30", "23:59:59", "12:00:00", "12:00:60"},

		// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
		"DATE_US":            {"04/21/2022", "12-25-2020", "07/04/1999"},
		"DATE_EU":            {"21.04.2022", "25/12/2020", "04-07-1999"},
		"ISO8601_TIMEZONE":   {"Z", "+02:00", "-05:00"},
		"ISO8601_SECOND":     {"59", "30", "60.123"},
		"TIMESTAMP_ISO8601":  {"2022-04-21T14:30:00Z", "2020-12-25T23:59:59+02:00", "1999-07-04T12:00:00-05:00"},
		"DATE":               {"04/21/2022", "21.04.2022", "12-25-2020"},
		"DATESTAMP":          {"04/21/2022 14:30", "21.04.2022 23:59", "12-25-2020 12:00"},
		"TZ":                 {"EST", "CET", "PDT"},
		"DATESTAMP_RFC822":   {"Wed Jan 12 2024 14:33 EST"},
		"DATESTAMP_RFC2822":  {"Tue, 12 Jan 2022 14:30 +0200", "Fri, 25 Dec 2020 23:59 -0500", "Sun, 04 Jul 1999 12:00 Z"},
		"DATESTAMP_OTHER":    {"Tue Jan 12 14:30 EST 2022", "Fri Dec 25 23:59 CET 2020", "Sun Jul 04 12:00 PDT 1999"},
		"DATESTAMP_EVENTLOG": {"20220421143000", "20201225235959", "19990704120000"},

		// Syslog Dates: Month Day HH:MM:SS	"MONTH":         `\b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|Mar(?:ch|z)?|Apr(?:il)?|May|i|Jun(?:e|i)?|Jul(?:y|i)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b`,
		"SYSLOGTIMESTAMP": {"Jan  1 00:00:00", "Mar 15 12:34:56", "Dec 31 23:59:59"},
		"PROG":            {"sshd", "kernel", "cron"},
		"SYSLOGPROG":      {"sshd[1234]", "kernel", "cron[5678]"},
		"SYSLOGHOST":      {"example.com", "192.168.1.1", "localhost"},
		"SYSLOGFACILITY":  {"<1.2>", "<12345.13456>"},
		"HTTPDATE":        {"25/Dec/2024:14:33 4"},
	}

	for name, values := range testCases {
		for i, sample := range values {
			t.Run(fmt.Sprintf("%s-%d", name, i), func(t *testing.T) {
				g := grok.New()

				pattern := fmt.Sprintf("%%{%s:result}", name)
				require.NoError(t, g.Compile(pattern, true))

				res, err := g.ParseString(sample)
				require.NoError(t, err)

				expKey := "result"
				val, found := res[expKey]
				require.True(t, found, "Key %q not found", expKey)
				require.Equal(t, sample, val)
			})
		}
	}
}

func TestCaptureGroups(t *testing.T) {
	testCases := []struct {
		pattern              string
		nco                  bool
		containsCaptureGroup bool
	}{
		{`\b\w+\b`, true, false},
		{`\b\w+\b`, false, false},
		{`%{WORD}`, true, false},
		{`%{WORD}`, false, true},
		{`%{SYSLOGTIMESTAMP:timestamp}`, true, true},
		{`%{SYSLOGTIMESTAMP:timestamp}`, false, true},
	}

	for i, tt := range testCases {
		t.Run(fmt.Sprintf("test-case-%d", i), func(t *testing.T) {
			g, err := grok.NewComplete()
			require.NoError(t, err)
			g.Compile(tt.pattern, tt.nco)
			require.Equal(t, tt.containsCaptureGroup, g.HasCaptureGroups())
		})
	}
}

func TestUnsupportedName(t *testing.T) {
	invalidPatterns := map[string]string{
		"INVALID:NAME": "val",
	}
	g, err := grok.NewWithPatterns(invalidPatterns)
	require.Nil(t, g)
	require.Equal(t, err, grok.ErrUnsupportedName)

	g, err = grok.NewComplete(invalidPatterns)
	require.Nil(t, g)
	require.Equal(t, err, grok.ErrUnsupportedName)

	g = grok.New()
	require.NotNil(t, g)
	err = g.AddPattern("INVALID:NAME", "val")
	require.Equal(t, err, grok.ErrUnsupportedName)

	// add also a valid one
	invalidPatterns["VALID"] = "*."
	err = g.AddPatterns(invalidPatterns)
	require.Equal(t, err, grok.ErrUnsupportedName)
}

func TestConvertMatch(t *testing.T) {
	testCases := []struct {
		Name                 string
		Pattern              string
		Text                 string
		ExpectedTypedMatches map[string]interface{}
		NamedCapturesOnly    bool
	}{
		{
			"NUMBER pattern with float",
			`Usage: %{NUMBER:usage}%{GREEDYDATA:ignore}`,
			"Usage: 24.3%",
			map[string]interface{}{
				"usage":  24.3,
				"ignore": "%",
			},
			true,
		},
		{
			"NUMBER pattern with int",
			`Usage: %{NUMBER:usage}%{GREEDYDATA:ignore}`,
			"Usage: 24%",
			map[string]interface{}{
				"usage":  float64(24),
				"ignore": "%",
			},
			true,
		},
		{
			"INT pattern with float",
			`Usage: %{INT:usage}%{GREEDYDATA:ignore}`,
			"Usage: 24.3%",
			map[string]interface{}{
				"usage":  24,
				"ignore": ".3%",
			},
			true,
		},
		{
			"INT pattern with int",
			`Usage: %{INT:usage}%{GREEDYDATA:ignore}`,
			"Usage: 24%",
			map[string]interface{}{
				"usage":  24,
				"ignore": "%",
			},
			true,
		},
		{
			"INT pattern with scale(1000)",
			`Usage: %{INT:usage:scale(1000)}%{GREEDYDATA:ignore}`,
			"Usage: 24%",
			map[string]interface{}{
				"usage":  int64(24000),
				"ignore": "%",
			},
			true,
		},
		{
			"NUMBER pattern with scale(1000)",
			`Usage: %{NUMBER:usage:scale(1000)}%{GREEDYDATA:ignore}`,
			"Usage: 24.3%",
			map[string]interface{}{
				"usage":  float64(24300),
				"ignore": "%",
			},
			true,
		},
		{
			`data keyvalue(": ")`,
			`%{GREEDYDATA:da.test:keyvalue(": ")}`,
			"user: john connect_date: 11/08/2017 id: 123 action: click",
			map[string]interface{}{
				"da.test": map[string]interface{}{
					"user":         "john",
					"connect_date": "11/08/2017",
					"id":           "123",
					"action":       "click",
				},
			},
			true,
		},
		{
			`data keyvalue("=","/:")`,
			`%{GREEDYDATA:da.test:keyvalue("=","/:")}`,
			"url=https://app.datadoghq.com/event/stream user=john",
			map[string]interface{}{
				"da.test": map[string]interface{}{
					"url":  "https://app.datadoghq.com/event/stream",
					"user": "john",
				},
			},
			true,
		},
		{
			`data keyvalue(": ") with no prefix`,
			`%{GREEDYDATA::keyvalue(": ")}`,
			"user: john connect_date: 11/08/2017 id: 123 action: click",
			map[string]interface{}{
				"user":         "john",
				"connect_date": "11/08/2017",
				"id":           "123",
				"action":       "click",
			},
			true,
		},
		{
			`data keyvalue("= ") with no prefix`,
			`%{GREEDYDATA::keyvalue("= ")}`,
			"user= john connect_date= 11/08/2017 id= 123 action= click",
			map[string]interface{}{
				"user":         "john",
				"connect_date": "11/08/2017",
				"id":           "123",
				"action":       "click",
			},
			true,
		},
		{
			`nested JSON`,
			`%{WORD:vm} %{WORD:app}\[%{number:logger.thread_id}\]: %{NOTSPACE:server} %{data::json}`,
			`vagrant program[123]: server.1 {"method":"GET", "status_code":200, "url":"https://app.datadoghq.com/logs/pipelines", "duration":123456}`,
			map[string]interface{}{
				"vm":               "vagrant",
				"app":              "program",
				"logger.thread_id": float64(123),
				"server":           "server.1",
				"method":           "GET",
				"status_code":      float64(200),
				"url":              "https://app.datadoghq.com/logs/pipelines",
				"duration":         float64(123456),
			},
			true,
		},
		{
			`nested JSON with param without name`,
			`%{word:vm} %{WORD:app}\[%{NUMBER}\]: %{NOTSPACE:server} %{data::json}`,
			`vagrant program[123]: server.1 {"method":"GET", "status_code":200, "url":"https://app.datadoghq.com/logs/pipelines", "duration":123456}`,
			map[string]interface{}{
				"vm":          "vagrant",
				"app":         "program",
				"server":      "server.1",
				"method":      "GET",
				"status_code": float64(200),
				"url":         "https://app.datadoghq.com/logs/pipelines",
				"duration":    float64(123456),
			},
			true,
		},
		{
			`non greedy data`,
			`%{date("yyyy-MM-dd HH:mm:ss z"):timestamp} \| %{notSpace:agent} \| %{word:level} \| \(%{notSpace:filename}:%{number:lineno} in %{word:process}\) \|( %{data::keyvalue(":")} \|)?( - \|)?( \(%{notSpace:pyFilename}:%{number:pyLineno}\) \|)?%{data}`,
			`2025-07-06 12:52:48 UTC | CORE | DEBUG | (pkg/collector/python/datadog_agent.go:150 in LogMessage) | network:4b0649b7e11f0772 | (check_linux.py:422) | Ethtool stat collection not configured`,
			map[string]interface{}{
				"timestamp":  int64(1751806368000),
				"agent":      "CORE",
				"level":      "DEBUG",
				"filename":   "pkg/collector/python/datadog_agent.go",
				"lineno":     float64(150),
				"process":    "LogMessage",
				"network":    "4b0649b7e11f0772",
				"pyFilename": "check_linux.py",
				"pyLineno":   float64(422),
			},
			true,
		},
		{
			`date fn: HH:mm:ss`,
			`%{date("HH:mm:ss"):date}`,
			`14:20:15`,
			map[string]interface{}{
				"date": int64(51615000),
			},
			true,
		},
		{
			`date fn: hh:mm:ss a`,
			`%{date("hh:mm:ss a"):date}`,
			`02:20:15 PM`,
			map[string]interface{}{
				"date": int64(51615000),
			},
			true,
		},
		{
			`date fn: EEE MMM dd HH:mm:ss yyyy with timezone +3`,
			`%{date("EEE MMM dd HH:mm:ss yyyy","+3"):date}`,
			`Thu Jun 16 08:29:03 2016`,
			map[string]interface{}{
				"date": int64(1466054943000),
			},
			true,
		},
		{
			`date fn: EEE MMM dd HH:mm:ss yyyy with timezone Europe/Paris`,
			`%{date("EEE MMM dd HH:mm:ss yyyy","Europe/Paris"):date}`,
			`Thu Jun 16 08:29:03 2016`,
			map[string]interface{}{
				"date": int64(1466058543000),
			},
			true,
		},
		{
			`date fn: dd/MM/yyyy`,
			`%{date("dd/MM/yyyy"):date}`,
			`11/10/2014`,
			map[string]interface{}{
				"date": int64(1412985600000),
			},
			true,
		},
		{
			`date fn: EEE MMM dd HH:mm:ss yyyy (no timezone)`,
			`%{date("EEE MMM dd HH:mm:ss yyyy"):date}`,
			`Thu Jun 16 08:29:03 2016`,
			map[string]interface{}{
				"date": int64(1466065743000),
			},
			true,
		},
		{
			`date fn: EEE MMM d HH:mm:ss yyyy (single-digit day)`,
			`%{date("EEE MMM d HH:mm:ss yyyy"):date}`,
			`Tue Nov 1 08:29:03 2016`,
			map[string]interface{}{
				"date": int64(1477988943000),
			},
			true,
		},
		{
			`date fn: dd/MMM/yyyy:HH:mm:ss Z`,
			`%{date("dd/MMM/yyyy:HH:mm:ss Z"):date}`,
			`06/Mar/2013:01:36:30 +0900`,
			map[string]interface{}{
				"date": int64(1362533790000),
			},
			true,
		},
		{
			`date fn: yyyy-MM-dd'T'HH:mm:ss.SSSZ`,
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSSZ"):date}`,
			`2016-11-29T16:21:36.431+0000`,
			map[string]interface{}{
				"date": int64(1480436496431),
			},
			true,
		},
		{
			`date fn: yyyy-MM-dd'T'HH:mm:ss.SSSZZ`,
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSSZZ"):date}`,
			`2016-11-29T16:21:36.431+00:00`,
			map[string]interface{}{
				"date": int64(1480436496431),
			},
			true,
		},
		{
			`date fn: dd/MMM/yyyy:HH:mm:ss.SSS`,
			`%{date("dd/MMM/yyyy:HH:mm:ss.SSS"):date}`,
			`06/Feb/2009:12:14:14.655`,
			map[string]interface{}{
				"date": int64(1233922454655),
			},
			true,
		},
		{
			`date fn: yyyy-MM-dd HH:mm:ss.SSS z`,
			`%{date("yyyy-MM-dd HH:mm:ss.SSS z"):date}`,
			`2007-08-31 19:22:22.427 ADT`,
			map[string]interface{}{
				"date": int64(1188588142427),
			},
			true,
		},
		{
			`regex fn: [a-z]*`,
			`%{regex("[a-z]*"):user.firstname}_%{regex("[a-zA-Z0-9]*"):user.id} .*`,
			`john_1a2b3c4 connected on 11/08/2017`,
			map[string]interface{}{
				"user.firstname": "john",
				"user.id":        "1a2b3c4",
			},
			true,
		},
		{
			"MMdd HH:mm:ss.SSSSSS format",
			`%{date("MMdd HH:mm:ss.SSSSSS"):date}`,
			"0601 14:20:25.000572",
			map[string]interface{}{
				"date": int64(13098025000),
			},
			true,
		},
		{
			"yyyy-MM-dd format",
			`%{date("yyyy-MM-dd"):date}`,
			"2023-06-15",
			map[string]interface{}{
				"date": int64(1686787200000),
			},
			true,
		},
		{
			"ISO8601 with timezone",
			`%{date("yyyy-MM-dd'T'HH:mm:ssZ"):date}`,
			"2023-06-15T14:20:25+0000",
			map[string]interface{}{
				"date": int64(1686838825000),
			},
			true,
		},
		{
			"US date format",
			`%{date("MM/dd/yyyy"):date}`,
			"06/15/2023",
			map[string]interface{}{
				"date": int64(1686787200000),
			},
			true,
		},
		{
			"EU date format",
			`%{date("dd/MM/yyyy"):date}`,
			"15/06/2023",
			map[string]interface{}{
				"date": int64(1686787200000),
			},
			true,
		},
		{
			"HTTP date format",
			`%{date("dd/MMM/yyyy:HH:mm:ss Z"):date}`,
			"15/Jun/2023:14:20:25 +0000",
			map[string]interface{}{
				"date": int64(1686838825000),
			},
			true,
		},
		{
			"Syslog timestamp format",
			`%{date("MMM dd HH:mm:ss"):date}`,
			"Jun 15 14:20:25",
			map[string]interface{}{
				"date": int64(14307625000),
			},
			true,
		},
		{
			"MMdd format",
			`%{date("MMdd"):date}`,
			"0615",
			map[string]interface{}{
				"date": int64(14256000000),
			},
			true,
		},
		{
			"ISO8601 without timezone",
			`%{date("yyyy-MM-dd'T'HH:mm:ss"):date}`,
			"2023-06-15T14:20:25",
			map[string]interface{}{
				"date": int64(1686838825000),
			},
			true,
		},
		{
			"Date with time",
			`%{date("yyyy-MM-dd HH:mm:ss"):date}`,
			"2023-06-15 14:20:25",
			map[string]interface{}{
				"date": int64(1686838825000),
			},
			true,
		},
		{
			"Time with milliseconds",
			`%{date("HH:mm:ss.SSS"):date}`,
			"14:20:25.123",
			map[string]interface{}{
				"date": int64(51625123),
			},
			true,
		},
		{
			"Time without milliseconds",
			`%{date("HH:mm:ss"):date}`,
			"14:20:25",
			map[string]interface{}{
				"date": int64(51625000),
			},
			true,
		},
		{
			"TIMESTAMP_ISO8601 - 1",
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSS"):date}`,
			"2019-10-21T15:13:23.419",
			map[string]interface{}{
				"date": int64(1571670803419),
			},
			true,
		},
		{
			"TIMESTAMP_ISO8601 - 2",
			`%{date("yyyy-MM-dd HH:mm:ss.SSS-0000"):date}`,
			"2022-02-10 11:20:01.638-0000",
			map[string]interface{}{
				"date": int64(1644492001638),
			},
			true,
		},
		{
			"ISO8601 with milliseconds and timezone",
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSSZ"):date}`,
			"2023-06-15T14:20:25.123+0000",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"ISO8601 with milliseconds and timezone (ZZ)",
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSSZZ"):date}`,
			"2023-06-15T14:20:25.123+00:00",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"US date with time and milliseconds",
			`%{date("MM/dd/yyyy, H:mm:ss.SSS"):date}`,
			"06/15/2023, 1:25:45.141",
			map[string]interface{}{
				"date": int64(1686792345141),
			},
			true,
		},
		{
			"US date with time, milliseconds and AM/PM",
			`%{date("MM/dd/yyyy, K:mm:ss.SSS a"):date}`,
			"06/15/2023, 1:25:45.141 PM",
			map[string]interface{}{
				"date": int64(1686835545141),
			},
			true,
		},
		{
			"Date with milliseconds and comma separator",
			`%{date("yyyy-MM-dd HH:mm:ss,SSS"):date}`,
			"2023-06-15 14:20:25,123",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"Date with milliseconds and dot separator",
			`%{date("yyyy-MM-dd HH:mm:ss.SSS"):date}`,
			"2023-06-15 14:20:25.123",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"Date with milliseconds and timezone",
			`%{date("yyyy-MM-dd HH:mm:ss.SSSZ"):date}`,
			"2023-06-15 14:20:25.123+0000",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"Date with milliseconds and timezone (ZZ)",
			`%{date("yyyy-MM-dd HH:mm:ss.SSSZZ"):date}`,
			"2023-06-15 14:20:25.123+00:00",
			map[string]interface{}{
				"date": int64(1686838825123),
			},
			true,
		},
		{
			"Date with year first",
			`%{date("yyyy/MM/dd HH:mm:ss"):date}`,
			"2024/03/18 14:56:36",
			map[string]interface{}{
				"date": int64(1710773796000),
			},
			true,
		},
		{
			"Date with month word",
			`%{date("dd/MMM/YYYY:HH:mm:ss"):date}`,
			"19/Jun/2023:16:04:12",
			map[string]interface{}{
				"date": int64(1687190652000),
			},
			true,
		},
		{
			"Date with rabbit 1",
			`%{date("d-MMM-yyyy::HH:mm:ss"):date}`,
			"8-Mar-2018::14:09:27",
			map[string]interface{}{
				"date": int64(1520518167000),
			},
			true,
		},
		{
			"Date with rabbit 2",
			`%{date("dd-MMM-yyyy::HH:mm:ss"):date}`,
			"08-Mar-2018::14:09:27",
			map[string]interface{}{
				"date": int64(1520518167000),
			},
			true,
		},
		{
			"Date with dd agent",
			`%{date("yyyy-MM-dd HH:mm:ss z"):date}`,
			"2019-02-01 16:59:41 UTC",
			map[string]interface{}{
				"date": int64(1549040381000),
			},
			true,
		},
		{
			"Date with elb",
			`%{date("yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"):date}`,
			"2015-05-13T23:39:43.945958Z",
			map[string]interface{}{
				"date": int64(1431560383945),
			},
			true,
		},
		{
			"Date with redis 1",
			`%{date("dd MMM HH:mm:ss.SSS"):date}`,
			"08 Jan 17:45:41.572",
			map[string]interface{}{
				"date": int64(668741572),
			},
			true,
		},
		{
			"Date with redis 2",
			`%{date("dd MMM yyyy HH:mm:ss.SSS"):date}`,
			"14 May 2019 19:11:40.164",
			map[string]interface{}{
				"date": int64(1557861100164),
			},
			true,
		},
		{
			"Date with python 1",
			`%{date("yyyy-MM-dd H:mm:ss,SSS"):date}`,
			"2019-01-07 15:20:15,972",
			map[string]interface{}{
				"date": int64(1546874415972),
			},
			true,
		},
		{
			"Date with python 2",
			`%{date("yyyy-MM-dd'T'HH:mm:ss','SSS"):date}`,
			"2017-12-19T14:37:58,995",
			map[string]interface{}{
				"date": int64(1513694278995),
			},
			true,
		},
		{
			"Date with etcd",
			`%{date("yyyy-MM-dd HH:mm:ss.SSSSSS"):date}`,
			"2020-08-20 18:23:44.721706",
			map[string]interface{}{
				"date": int64(1597947824721),
			},
			true,
		},
		{
			"Date with elasticsearch",
			`%{date("yyyy-MM-dd'T'HH:mm:ss,SSS"):date}`,
			"2023-08-24T06:20:10,847",
			map[string]interface{}{
				"date": int64(1692858010847),
			},
			true,
		},
		{
			"Date with keda",
			`%{date("MMDD HH:mm:ss.SSSSSS"):date}`,
			"1216 14:53:06.680302",
			map[string]interface{}{
				"date": int64(30207186680),
			},
			true,
		},
		{
			"Date with datadog tracer",
			`%{date("yyyy-MM-dd HH:mm:ss.SSS Z"):date}`,
			"2022-01-27 13:51:31.805 +0000",
			map[string]interface{}{
				"date": int64(1643291491805),
			},
			true,
		},
		{
			"Date with rabbitmq",
			`%{date("yyyy-MM-dd HH:mm:ss.SSSSSSZZ"):date}`,
			"2022-04-18 22:52:43.608049+00:00",
			map[string]interface{}{
				"date": int64(1650322363608),
			},
			true,
		},
		{
			"nullIf simple empty return",
			`%{notSpace:http.ident:nullIf("-")}`,
			`-`,
			map[string]interface{}{},
			true,
		},
		{
			"nullIf simple with return",
			`%{notSpace:http.ident:nullIf("-")}`,
			`400`,
			map[string]interface{}{
				"http.ident": "400",
			},
			true,
		},
		{
			"nullIf complecated pattern",
			`%{ipOrHost:network.client.ip} %{notSpace:http.ident:nullIf("-")} %{notSpace:http.auth:nullIf("-")} \[%{date("dd/MMM/yyyy:HH:mm:ss Z"):date_access}\] "(?:%{word:http.method} |)%{notSpace:http.url}(?: HTTP\/%{regex("\\d+\\.\\d+"):http.version}|)" %{number:http.status_code} (?:%{number:network.bytes_written}|-) "%{notSpace:http.referer}" "%{regex("[^\\\"]*"):http.useragent}".*`,
			`::1 - - [21/Oct/2019:19:16:34 +0000] "GET / HTTP/1.1" 504 - "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"`,
			map[string]interface{}{
				"http.referer":      "-",
				"http.status_code":  float64(504),
				"http.method":       "GET",
				"http.useragent":    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36",
				"http.version":      "1.1",
				"http.url":          "/",
				"network.client.ip": "::1",
				"date_access":       int64(1571685394000),
			},
			true,
		},
		{
			"regex or 1",
			`(%{integer:user.id}|%{word:user.firstname}) connected on %{date("MM/dd/yyyy"):connect_date}`,
			`john connected on 11/08/2017`,
			map[string]interface{}{
				"user.firstname": "john",
				"connect_date":   int64(1510099200000),
			},
			true,
		},
		{
			"regex or 2",
			`(%{integer:user.id}|%{word:user.firstname}) connected on %{date("MM/dd/yyyy"):connect_date}`,
			`12345 connected on 11/08/2017`,
			map[string]interface{}{
				"user.id":      12345,
				"connect_date": int64(1510099200000),
			},
			true,
		},
		{
			"Pattern with number modifier",
			`%{port:network.client.port:number}`,
			`8080`,
			map[string]interface{}{
				"network.client.port": float64(8080),
			},
			true,
		},
		{
			"Pattern with numberStr",
			`%{numberStr:network.client.port}`,
			`8080`,
			map[string]interface{}{
				"network.client.port": "8080",
			},
			true,
		},
		{
			"Pattern with integerStr",
			`%{integerStr:network.client.port}`,
			`8080`,
			map[string]interface{}{
				"network.client.port": "8080",
			},
			true,
		},
		{
			"Pattern with )",
			"systemOS=%{regex(\"[^,)]+\"):OS}",
			`systemOS=Linux 6.1.128`,
			map[string]interface{}{
				"OS": "Linux 6.1.128",
			},
			true,
		},
		{
			`:array("[]",",")`,
			`Users %{data:users:array("[]",",")} have been added to the database`,
			`Users [John, Oliver, Marc, Tom] have been added to the database`,
			map[string]interface{}{
				"users": []string{"John", " Oliver", " Marc", " Tom"},
			},
			true,
		},
		{
			`:array(",")`,
			`Users %{data:users:array(",")} have been added to the database`,
			`Users John, Oliver, Marc, Tom have been added to the database`,
			map[string]interface{}{
				"users": []string{"John", " Oliver", " Marc", " Tom"},
			},
			true,
		},
		{
			`cast querystring`,
			`%{notSpace:http.url_details.queryString:querystring}`,
			`?productId=superproduct&promotionCode=superpromo`,
			map[string]interface{}{
				"http.url_details.queryString": map[string]string{
					"productId":     "superproduct",
					"promotionCode": "superpromo",
				},
			},
			true,
		},
		{
			`cast rubyhash`,
			`%{data:info:rubyhash}`,
			`{:status=>500, :request_method=>"GET", :path_info=>"/_node/stats", :query_string=>"", :http_version=>"HTTP/1.1", :http_accept=>"*/*"}`,
			map[string]interface{}{
				"info": map[string]interface{}{
					"http_accept":    "*/*",
					"http_version":   "HTTP/1.1",
					"path_info":      "/_node/stats",
					"query_string":   "",
					"request_method": "GET",
					"status":         int64(500),
				},
			},
			true,
		},
		{
			`cast rubyhash flat`,
			`%{data::rubyhash}`,
			`{:status=>500, :request_method=>"GET", :path_info=>"/_node/stats", :query_string=>"", :http_version=>"HTTP/1.1", :http_accept=>"*/*"}`,
			map[string]interface{}{
				"http_accept":    "*/*",
				"http_version":   "HTTP/1.1",
				"path_info":      "/_node/stats",
				"query_string":   "",
				"request_method": "GET",
				"status":         int64(500),
			},
			true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.New()

			require.NoError(t, g.Compile(tt.Pattern, tt.NamedCapturesOnly))

			res, err := g.ParseTypedString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedTypedMatches), len(res))

			for k, v := range tt.ExpectedTypedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}
