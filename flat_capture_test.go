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
	"testing"

	"github.com/elastic/go-grok"
	"github.com/stretchr/testify/require"
)

// Keep the captured policy's bare keyvalue hint: it discards only its anonymous
// capture. The separate named word captures still extract both trace IDs.
const optionalJSONPattern = `(?:\[%{data::keyvalue}dd.trace_id=%{word:dd.trace_id} dd.span_id=%{word:dd.span_id}\]\s*)?%{data::json}`

func TestFlatCaptureConversionsAreIndependent(t *testing.T) {
	cases := []struct {
		name, body string
		want       map[string]interface{}
	}{
		{"plain_json", `{"answer":42,"nested":{"ok":true}}`, map[string]interface{}{"answer": float64(42), "nested": map[string]interface{}{"ok": true}}},
		{"prefixed_json", `[service=test dd.trace_id=123 dd.span_id=456] {"answer":42}`, map[string]interface{}{"dd.trace_id": "123", "dd.span_id": "456", "answer": float64(42)}},
		{"malformed_json_keeps_prefix", `[service=test dd.trace_id=123 dd.span_id=456] malformed`, map[string]interface{}{"dd.trace_id": "123", "dd.span_id": "456"}},
		{"empty_json", `{}`, map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, e := grok.NewComplete()
			require.NoError(t, e)
			require.NoError(t, g.Compile(optionalJSONPattern, true))
			actual, e := g.ParseTypedString(tc.body)
			require.NoError(t, e)
			require.Equal(t, tc.want, actual)
		})
	}
}

func TestRepeatedFlatCapturesAndNestedDefinitions(t *testing.T) {
	g, e := grok.NewComplete()
	require.NoError(t, e)
	require.NoError(t, g.AddPatterns(map[string]string{"PART": `%{data::json}`}))
	require.NoError(t, g.Compile(`^%{PART} SEP %{PART}$`, true))
	got, e := g.ParseTypedString(`{"a":1,"shared":"first"} SEP {"b":2,"shared":"last"}`)
	require.NoError(t, e)
	require.Equal(t, map[string]interface{}{"a": float64(1), "b": float64(2), "shared": "last"}, got)
	require.NoError(t, g.Compile(`%{WORD:value}`, true))
	got, e = g.ParseTypedString("recompiled")
	require.NoError(t, e)
	require.Equal(t, map[string]interface{}{"value": "recompiled"}, got)
}

func TestFlatCaptureInternalNameDoesNotHideUserField(t *testing.T) {
	g, err := grok.NewComplete()
	require.NoError(t, err)
	require.NoError(t, g.AddPatterns(map[string]string{"PREFIX": `%{WORD:FLAT_TO_ROOT.dup1}`}))
	require.NoError(t, g.Compile(`^%{PREFIX} %{data::json} SEP %{data::json}$`, true))
	got, err := g.ParseTypedString(`value {"a":1} SEP {"b":2}`)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"FLAT_TO_ROOT.dup1": "value", "a": float64(1), "b": float64(2)}, got)
}

func TestFlatCaptureFieldPrecedence(t *testing.T) {
	cases := []struct {
		name, pattern, body string
		want                map[string]interface{}
	}{
		{"json_after_named_capture", `^%{WORD:field} %{data::json}$`, `prefix {"field":42}`, map[string]interface{}{"field": float64(42)}},
		{"named_capture_after_json", `^%{data::json} %{WORD:field}$`, `{"field":42} suffix`, map[string]interface{}{"field": "suffix"}},
		{"trace_prefix_collision", optionalJSONPattern, `[dd.trace_id=123 dd.span_id=456] {"dd.trace_id":999}`, map[string]interface{}{"dd.trace_id": float64(999), "dd.span_id": "456"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := grok.NewComplete()
			require.NoError(t, err)
			require.NoError(t, g.Compile(tc.pattern, true))
			actual, err := g.ParseTypedString(tc.body)
			require.NoError(t, err)
			require.Equal(t, tc.want, actual)
			actual, err = g.ParseTyped([]byte(tc.body))
			require.NoError(t, err)
			require.Equal(t, tc.want, actual)
		})
	}
}

func TestFlatKeyValueAndJSONConversionsAreIndependent(t *testing.T) {
	g, err := grok.NewComplete()
	require.NoError(t, err)
	require.NoError(t, g.Compile(`^%{data::keyvalue()} SEP %{data::json}$`, true))
	got, err := g.ParseTypedString(`service=test SEP {"answer":42}`)
	require.NoError(t, err)
	require.Equal(t, map[string]interface{}{"service": "test", "answer": float64(42)}, got)
}

func TestDuplicateCaptureAliasesPreserveUserNames(t *testing.T) {
	cases := []struct{ name, pattern, body string }{
		{"multiple_duplicates", `^%{INT:value:int} %{INT:value:int} %{INT:value:int} %{WORD:value.dup1}$`, "1 3 2 original"},
		{"user_name_after", `^%{INT:value:int} %{INT:value:int} %{WORD:value.dup1}$`, "1 2 original"},
		{"user_name_before", `^%{WORD:value.dup1} %{INT:value:int} %{INT:value:int}$`, "original 1 2"},
		{"nested_user_name", `^%{INT:value:int} %{INT:value:int} %{USER_FIELD}$`, "1 2 original"},
		{"raw_regex_name", `^%{INT:value:int} %{INT:value:int} (?P<value___dup1>original)$`, "1 2 original"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := grok.NewComplete()
			require.NoError(t, err)
			require.NoError(t, g.AddPatterns(map[string]string{"USER_FIELD": `%{WORD:value.dup1}`}))
			require.NoError(t, g.Compile(tc.pattern, true))
			typed, err := g.ParseTypedString(tc.body)
			require.NoError(t, err)
			require.Equal(t, map[string]interface{}{"value": 2, "value.dup1": "original"}, typed)
			typedBytes, err := g.ParseTyped([]byte(tc.body))
			require.NoError(t, err)
			require.Equal(t, typed, typedBytes)
			raw, err := g.ParseString(tc.body)
			require.NoError(t, err)
			require.Equal(t, map[string]string{"value": "2", "value.dup1": "original"}, raw)
			rawBytes, err := g.Parse([]byte(tc.body))
			require.NoError(t, err)
			require.Equal(t, map[string][]byte{"value": []byte("2"), "value.dup1": []byte("original")}, rawBytes)
		})
	}
}
