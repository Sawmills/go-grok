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

package grok

import (
	"encoding/json"
	"fmt"
	"github.com/elastic/go-grok/parsers"
	"github.com/elastic/go-grok/regexp"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-grok/patterns"
)

const dotSep = "___"

var (
	ErrParseFailure    = fmt.Errorf("parsing failed")
	ErrTypeNotProvided = fmt.Errorf("type not specified")
	ErrUnsupportedName = fmt.Errorf("name contains unsupported character ':'")

	FlatToRoot = "FLAT_TO_ROOT"
	// grok can be specified in either of these forms:
	// %{SYNTAX} - e.g {NUMBER}
	// %{SYNTAX:ID} - e.g {NUMBER:MY_AGE}
	// %{SYNTAX:ID:TYPE} - e.g {NUMBER:MY_AGE:INT}
	// supported types are int, long, double, float and boolean
	// for go specific implementation int and long results in int
	// double and float both results in float
	reusePattern    = regexp.MustCompile(`%{((?:\w+|(?:\w+\("(?:[^"]|\\")*"(?:,\s*"[^"]*")?)\))(?::[\w+.]*(?::(?:\w+|\w+\([^)]*\)))?)?)}`)
	functionPattern = regexp.MustCompile(`(\w+)\(([^)]*)\)`)
	delimiterRegex  = regexp.MustCompile("[ ,;]")
)

var patternDefaultsMappings = map[string]string{
	// Direct 1:1 mappings where the matcher name matches the pattern name
	"notSpace":     "NOTSPACE",
	"word":         "WORD",
	"quotedString": "QUOTEDSTRING",
	"uuid":         "UUID",
	"mac":          "MAC",
	"ipv4":         "IPV4",
	"ipv6":         "IPV6",
	"ip":           "IP",
	"hostname":     "HOSTNAME",
	"ipOrHost":     "IPORHOST",

	// Numeric types
	"number":        "NUMBER",
	"numberStr":     "NUMBER",
	"numberExt":     "BASE10NUM",
	"numberExtStr":  "BASE10NUM",
	"integer":       "INT",
	"integerStr":    "INT",
	"integerExt":    "INT",
	"integerExtStr": "INT",

	// String types
	"doubleQuotedString": "QUOTEDSTRING", // Subset of QUOTEDSTRING
	"singleQuotedString": "QUOTEDSTRING", // Subset of QUOTEDSTRING

	// Special cases
	"boolean": "BOOL",
	"port":    "POSINT",
	"data":    "GREEDYDATA",
}

var dateReplacements = []struct {
	pattern      string
	regex        string
	goTimeFormat string
}{
	// Year patterns
	{"yyyy", `\d{4}`, "2006"}, // Four-digit year (2018)
	{"YYYY", `\d{4}`, "2006"}, // Four-digit year (2018)
	{"yy", `\d{2}`, "06"},     // Two-digit year (18)

	// Month patterns
	{"MMMM", `(?:January|February|March|April|May|June|July|August|September|October|November|December)`, "January"}, // Full month name
	{"MMM", `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`, "Jan"},                                            // Abbreviated month name
	{"MM", `(?:0[1-9]|1[0-2])`, "01"}, // Two-digit month (01-12)
	{"M", `(?:[1-9]|1[0-2])`, "1"},    // One-digit month (1-12)

	// Day of month patterns
	{"dd", `(?:0[1-9]|[12][0-9]|3[01])`, "02"}, // Two-digit day (01-31)
	{"d", `(?:[1-9]|[12][0-9]|3[01])`, "2"},    // One-digit day (1-31)
	{"DD", `(?:0[1-9]|[12][0-9]|3[01])`, "02"}, // Two-digit day (01-31)

	// Day of week patterns
	{"EEE", `(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)`, "Mon"}, // Three-letter day name

	// Hour patterns (24-hour)
	{"HH", `(?:[01][0-9]|2[0-3])`, "15"},   // Two-digit hour, 24-hour (00-23)
	{"H", `(?:[0-9]|1[0-9]|2[0-3])`, "15"}, // One-digit hour, 24-hour (0-23)

	// Hour patterns (12-hour)
	{"hh", `(?:0[1-9]|1[0-2])`, "03"}, // Two-digit hour, 12-hour (01-12)
	{"h", `(?:[1-9]|1[0-2])`, "3"},    // One-digit hour, 12-hour (1-12)
	{"K", `(?:[0-9]|1[01])`, "3"},     // One-digit hour, 12-hour (0-11)

	// Minute patterns
	{"mm", `[0-5][0-9]`, "04"},         // Two-digit minute (00-59)
	{"m", `(?:[0-9]|[1-5][0-9])`, "4"}, // One-digit minute (0-59)

	// Second patterns
	{"ss", `[0-5][0-9]`, "05"},         // Two-digit second (00-59)
	{"s", `(?:[0-9]|[1-5][0-9])`, "5"}, // One-digit second (0-59)

	// Millisecond pattern
	{"SSS", `\d{3}`, "000"},         // Milliseconds, 3-digits (000-999)
	{"SSSSSS", `\d{6}`, "000000"},   // Microseconds, 6-digits
	{"SSSSSSS", `\d{7}`, "0000000"}, // 7-digit precision

	// Timezone patterns
	{"Z", `%{ISO8601_TIMEZONE}`, "Z0700"},
	{"ZZ", `%{ISO8601_TIMEZONE}`, "Z07:00"},
	{"z", `%{TZ}`, "MST"}, // UTC offset, ±HH:mm format

	// AM/PM patterns - These should be handled last to avoid conflicts
	{"a", `(?:AM|PM)`, "PM"}, // Uppercase AM/PM
}

type Grok struct {
	patternDefinitions    map[string]string
	re                    regexp.Matcher
	typeHints             map[string][]string
	lookupDefaultPatterns bool
	rubyHashParser        parsers.RubyHashParser
}

func New() *Grok {
	return &Grok{
		patternDefinitions:    make(map[string]string),
		lookupDefaultPatterns: true,
		rubyHashParser:        parsers.RubyHashParser{},
	}
}

func NewWithoutDefaultPatterns() *Grok {
	return &Grok{
		patternDefinitions: make(map[string]string),
	}
}

func NewWithPatterns(patterns ...map[string]string) (*Grok, error) {
	g := &Grok{
		patternDefinitions:    make(map[string]string),
		lookupDefaultPatterns: true,
	}

	for _, p := range patterns {
		if err := g.AddPatterns(p); err != nil {
			return nil, err
		}
	}

	return g, nil
}

// NewComplete creates a grok parser with full set of patterns
func NewComplete(additionalPatterns ...map[string]string) (*Grok, error) {
	g, err := NewWithPatterns(
		patterns.AWS,
		patterns.Bind9,
		patterns.Bro,
		patterns.Exim,
		patterns.HAProxy,
		patterns.Httpd,
		patterns.Firewalls,
		patterns.Java,
		patterns.Junos,
		patterns.Maven,
		patterns.MCollective,
		patterns.MongoDB,
		patterns.PostgreSQL,
		patterns.Rails,
		patterns.Redis,
		patterns.Ruby,
		patterns.Squid,
		patterns.Syslog,
	)
	if err != nil {
		return nil, err
	}

	for _, p := range additionalPatterns {
		if err := g.AddPatterns(p); err != nil {
			return nil, err
		}
	}

	return g, nil
}

func (grok *Grok) AddPattern(name, patternDefinition string) error {
	if strings.ContainsRune(name, ':') {
		return ErrUnsupportedName
	}

	// overwrite existing if present
	grok.patternDefinitions[name] = patternDefinition
	return nil
}

func (grok *Grok) AddPatterns(patternDefinitions map[string]string) error {
	// overwrite existing if present
	for name, patternDefinition := range patternDefinitions {
		if strings.ContainsRune(name, ':') {
			return ErrUnsupportedName
		}

		grok.patternDefinitions[name] = patternDefinition
	}
	return nil
}

func (grok *Grok) HasCaptureGroups() bool {
	if grok == nil || grok.re == nil {
		return false
	}

	for _, groupName := range grok.re.SubexpNames() {
		if groupName != "" {
			return true
		}
	}

	return false
}

func (grok *Grok) Compile(pattern string, namedCapturesOnly bool) error {
	return grok.compile(pattern, namedCapturesOnly)
}

func (grok *Grok) Match(text []byte) bool {
	return grok.re.Match(text)
}

func (grok *Grok) MatchString(text string) bool {
	return grok.re.MatchString(text)
}

// ParseString parses text in a form of string and returns map[string]string with values
// not converted to types according to hints.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseString(text string) (map[string]string, error) {
	return grok.captureString(text)
}

// Parse parses text in a form of []byte and returns map[string][]byte with values
// not converted to types according to hints.
// When expression is not a match nil map is returned.
func (grok *Grok) Parse(text []byte) (map[string][]byte, error) {
	return grok.captureBytes(text)
}

// ParseTyped parses text and returns map[string]interface{} with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseTyped(text []byte) (map[string]interface{}, error) {
	captures, err := grok.captureTyped(text)
	if err != nil {
		return nil, err
	}

	captureBytes := make(map[string]interface{})
	for k, v := range captures {
		captureBytes[k] = v
	}

	return captureBytes, nil
}

// ParseTypedString parses text and returns map[string]interface{} with values
// typed according to type hints generated at compile time.
// If hint is not found error returned is TypeNotProvided.
// When expression is not a match nil map is returned.
func (grok *Grok) ParseTypedString(text string) (map[string]interface{}, error) {
	return grok.ParseTyped([]byte(text))
}

func (grok *Grok) compile(pattern string, namedCapturesOnly bool) error {
	// get expanded pattern
	expandedExpression, hints, err := grok.expand(pattern, namedCapturesOnly)
	if err != nil {
		return err
	}

	compiledExpression, err := regexp.Compile(expandedExpression)
	if err != nil {
		return err
	}

	grok.re = compiledExpression
	grok.typeHints = hints

	return nil
}

func (grok *Grok) captureString(text string) (map[string]string, error) {
	return captureTypeFn(grok.re, text,
		func(v, _ string) (string, error) {
			return v, nil
		},
	)
}

func (grok *Grok) captureBytes(text []byte) (map[string][]byte, error) {
	return captureTypeFn(grok.re, string(text),
		func(v, _ string) ([]byte, error) {
			return []byte(v), nil
		},
	)
}

func (grok *Grok) captureTyped(text []byte) (map[string]interface{}, error) {
	return captureTypeFn(grok.re, string(text), grok.convertMatchAll)
}

func mergeCaptureMaps[T any, K comparable, V any](source T, target map[K]V) (map[K]V, bool) {
	// Use reflection to check if source is a map
	sourceValue := reflect.ValueOf(source)
	if sourceValue.Kind() != reflect.Map {
		return target, false // Not a map, return original target
	}

	// Iterate through source map keys
	for _, key := range sourceValue.MapKeys() {
		// Get value for the key
		value := sourceValue.MapIndex(key)

		// Convert key and value to the target map's types
		// This requires type assertions, which might panic if incompatible
		targetKey, ok := key.Interface().(K)
		if !ok {
			continue // Skip if key type cannot be converted
		}

		targetValue, ok := value.Interface().(V)
		if !ok {
			continue // Skip if value type cannot be converted
		}

		// Add to target map
		target[targetKey] = targetValue
	}

	return target, true
}

func safeIsNil(i interface{}) bool {
	if i == nil {
		return true
	}

	v := reflect.ValueOf(i)

	// Check if the value is valid first
	if !v.IsValid() {
		return true
	}

	// Check based on the kind of value
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.UnsafePointer, reflect.Interface, reflect.Slice:
		return v.IsNil()
	default:
		// For types that can't be nil (int, string, struct, etc.)
		return false
	}
}

func captureTypeFn[K any](re regexp.Matcher, text string, conversionFn func(v, key string) (K, error)) (map[string]K, error) {
	captures := make(map[string]K)

	matches := re.FindStringSubmatch(text)
	if len(matches) == 0 {
		return captures, nil
	}

	names := re.SubexpNames()
	if len(names) == 0 {
		return captures, nil
	}

	for i, name := range names {
		if len(name) == 0 {
			continue
		}

		match := matches[i]
		if len(match) == 0 {
			continue
		}

		if conversionFn != nil {
			v, err := conversionFn(string(match), name)
			if err != nil {
				return nil, err
			}
			if safeIsNil(v) {
				continue
			}
			if name == FlatToRoot {
				var merged bool
				captures, merged = mergeCaptureMaps(v, captures)
				if !merged {
					return nil, fmt.Errorf("failed to merge capture maps: %w", ErrParseFailure)
				}
			} else {
				captures[strings.ReplaceAll(name, dotSep, ".")] = v
			}
		}
	}

	return captures, nil
}

func (grok *Grok) convertMatchAll(match, name string) (interface{}, error) {
	hint, found := grok.typeHints[name]
	if !found || len(hint) == 0 {
		return match, nil
	}
	var matchAfterConvert interface{} = match
	for _, h := range hint {
		matchAfterConvert = grok.convertMatch(matchAfterConvert, h, name)
	}
	return matchAfterConvert, nil
}

func parseStringToNumber(s string) (interface{}, error) {
	if intVal, err := strconv.ParseInt(s, 10, 64); err == nil {
		return intVal, nil
	}

	if floatVal, err := strconv.ParseFloat(s, 64); err == nil {
		return floatVal, nil
	}

	return nil, fmt.Errorf("failed to parse %q", s)
}

type KeyValueOptions struct {
	SeparatorStr string
	//TODO add support
	CharacterAllowList string
	//TODO add support
	QuotingStr string
	//TODO add support
	Delimiter string
}

func defaultKeyValueOptions() KeyValueOptions {
	return KeyValueOptions{
		SeparatorStr:       "=",
		CharacterAllowList: "",
		QuotingStr:         "",    // Empty means use default quotes detection: <>, "", ''
		Delimiter:          " ,;", // Space, comma, and semicolon
	}
}

func splitArgsByComma(s string) []string {
	var result []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, char := range s {
		if (char == '"' || char == '\'') && (quoteChar == 0 || quoteChar == char) {
			inQuote = !inQuote
			if inQuote {
				quoteChar = char
			} else {
				quoteChar = 0
			}
			current.WriteRune(char)
		} else if char == ',' && !inQuote {
			result = append(result, current.String())
			current.Reset()
		} else {
			current.WriteRune(char)
		}
	}

	// Add the last part
	result = append(result, current.String())

	return result
}

func unquoteString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func parseKeyValueArgs(args []string) KeyValueOptions {
	options := defaultKeyValueOptions()

	// If no args provided, use defaults
	if len(args) == 0 {
		return options
	}

	// Apply the arguments based on their position
	if len(args) >= 1 && args[0] != "" {
		options.SeparatorStr = unquoteString(args[0])
	}

	if len(args) >= 2 && args[1] != "" {
		options.CharacterAllowList = unquoteString(args[1])
	}

	if len(args) >= 3 && args[2] != "" {
		options.QuotingStr = unquoteString(args[2])
	}

	if len(args) >= 4 && args[3] != "" {
		options.Delimiter = unquoteString(args[3])
	}

	return options
}

func parseKeyValuePairs(pairs []string, delimiter string) (map[string]any, error) {
	parsed := make(map[string]any)
	for _, p := range pairs {
		pair := strings.SplitN(p, delimiter, 2)
		if len(pair) != 2 {
			continue
		}

		key := strings.TrimSpace(pair[0])
		value := strings.TrimSpace(pair[1])

		parsed[key] = value
	}
	return parsed, nil
}

func splitStringToPairs(input string, options KeyValueOptions) ([]string, error) {
	var pairs []string

	// Split the input by delimiter
	segments := delimiterRegex.Split(input, -1)
	var currentPair strings.Builder

	separatorStrTrimmed := strings.TrimSpace(options.SeparatorStr)
	for _, segment := range segments {
		if strings.HasSuffix(currentPair.String(), separatorStrTrimmed) && segment != "" {
			currentPair.WriteString(" ")
			currentPair.WriteString(segment)
		} else if currentPair.Len() > 0 {
			// Add the previous pair if it's not empty
			pairs = append(pairs, currentPair.String())
			currentPair.Reset()
			currentPair.WriteString(segment)
		} else {
			// Start a new pair
			currentPair.WriteString(segment)
		}
	}

	// Add the last pair if it's not empty
	if currentPair.Len() > 0 {
		pairs = append(pairs, currentPair.String())
	}

	return pairs, nil
}

func timeToEpochMillis(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}

func parseDateString(dateStr string, goFormat string, timezone string) (time.Time, error) {
	// Handle timezone
	var loc *time.Location
	var err error

	if timezone == "" || timezone == "Z" || timezone == "UTC" {
		loc = time.UTC
	} else if strings.HasPrefix(timezone, "+") || strings.HasPrefix(timezone, "-") {
		// Parse numeric timezone offset (e.g. "+3")
		hours, err := strconv.Atoi(timezone)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid timezone offset: %s", timezone)
		}
		loc = time.FixedZone("Custom", hours*3600)
	} else {
		// Try to load the timezone by name
		loc, err = time.LoadLocation(timezone)
		if err != nil {
			return time.Time{}, fmt.Errorf("unknown timezone: %s", timezone)
		}
	}

	// Parse the date using Go's standard time package
	parsedTime, err := time.ParseInLocation(goFormat, dateStr, loc)
	if err != nil {
		return time.Time{}, err
	}
	year := parsedTime.Year()
	month := parsedTime.Month()
	day := parsedTime.Day()
	hour := parsedTime.Hour()
	minute := parsedTime.Minute()
	second := parsedTime.Second()
	nanosecond := parsedTime.Nanosecond()

	// Set default values if needed
	if year == 0 {
		year = 1970
	}

	return time.Date(year, month, day, hour, minute, second, nanosecond, loc), nil
}

type ParseFunction struct {
	Name string
	Args []string
}

func parseFunction(funcStr string) *ParseFunction {
	// Find the function name (everything before the first open parenthesis)
	nameEndIndex := strings.Index(funcStr, "(")
	if nameEndIndex == -1 {
		return nil // No opening parenthesis found
	}

	name := strings.TrimSpace(funcStr[:nameEndIndex])

	// Now extract everything between the outermost parentheses
	remainingStr := funcStr[nameEndIndex:]

	// Track parentheses and quotes
	parenCount := 0
	inQuotes := false
	argsStart := -1
	argsEnd := -1

	for i := 0; i < len(remainingStr); i++ {
		char := rune(remainingStr[i])

		// Handle escape sequences
		if char == '\\' && i+1 < len(remainingStr) {
			// Skip the backslash and the escaped character
			i++
			continue
		}

		if char == '"' {
			// Toggle quote state only for non-escaped quotes
			// (We already handled escape sequences above)
			inQuotes = !inQuotes
		} else if char == '(' && !inQuotes {
			parenCount++
			if parenCount == 1 {
				argsStart = i + 1 // Start of arguments (after opening parenthesis)
			}
		} else if char == ')' && !inQuotes {
			parenCount--
			if parenCount == 0 {
				argsEnd = i // End of arguments (before closing parenthesis)
				break
			}
		}
	}

	if argsStart == -1 || argsEnd == -1 || argsStart > argsEnd {
		return nil // Invalid function format
	}

	args := remainingStr[argsStart:argsEnd]

	return &ParseFunction{
		Name: name,
		Args: splitArgsByComma(args),
	}
}

func extractBetweenTags(input, startTag, endTag string) string {
	// Find the start position
	startPos := strings.Index(input, startTag)
	if startPos == -1 {
		return "" // Start tag not found
	}

	// Adjust startPos to be after the start tag
	startPos += len(startTag)

	// Find the end position, starting from after the start tag
	endPos := strings.Index(input[startPos:], endTag)
	if endPos == -1 {
		return "" // End tag not found
	}

	// The end position is relative to startPos, so adjust it
	endPos += startPos

	// Extract the content between the tags
	return input[startPos:endPos]
}

func (grok *Grok) convertMatch(match interface{}, hint, name string) interface{} {
	switch hint {
	case "string":
		str := fmt.Sprintf("%v", match)
		return str
	case "double", "float", "number":
		result, err := strconv.ParseFloat(fmt.Sprintf("%v", match), 64)
		if err != nil {
			return nil
		}
		return result
	case "int", "long", "integer":
		result, err := strconv.Atoi(fmt.Sprintf("%v", match))
		if err != nil {
			return nil
		}
		return result
	case "bool", "boolean":
		result, err := strconv.ParseBool(fmt.Sprintf("%v", match))
		if err != nil {
			return nil
		}
		return result
	case "json":
		var result map[string]interface{}
		_ = json.Unmarshal([]byte(fmt.Sprintf("%v", match)), &result)
		return result
	case "querystring":
		queryStr := strings.TrimPrefix(fmt.Sprintf("%v", match), "?")
		values, err := url.ParseQuery(queryStr)
		if err != nil {
			return nil
		}
		result := make(map[string]string)
		for key, val := range values {
			if len(val) > 0 {
				result[key] = val[0]
			}
		}
		return result
	case "rubyhash":
		result, err := grok.rubyHashParser.Parse(fmt.Sprintf("%v", match))
		if err != nil {
			return nil
		}
		return result
	default:
		parseResult := parseFunction(hint)
		if parseResult != nil {
			functionName := parseResult.Name
			args := parseResult.Args
			switch functionName {
			case "array":
				if str, ok := match.(string); !ok {
					return nil
				} else {
					if len(args) == 1 {
						return strings.Split(str, unquoteString(args[0]))
					}
					if len(args) == 2 {
						openCloseStr := unquoteString(args[0])
						openCloseStrParts := strings.Split(openCloseStr, "")
						startTag := openCloseStrParts[0]
						endTag := openCloseStrParts[1]
						content := extractBetweenTags(str, startTag, endTag)
						return strings.Split(content, unquoteString(args[1]))
					}
					return nil
				}
			case "nullIf":
				if match == unquoteString(args[0]) {
					return nil
				}
				return match
			case "dateformat":
				if str, ok := match.(string); !ok {
					return nil
				} else {
					if len(args) == 2 {
						t, err := parseDateString(str, unquoteString(args[0]), unquoteString(args[1]))
						if err != nil {
							return nil
						}
						return timeToEpochMillis(t)
					}
					t, err := parseDateString(str, unquoteString(args[0]), "")
					if err != nil {
						return nil
					}
					return timeToEpochMillis(t)
				}
			case "keyvalue":
				options := parseKeyValueArgs(args)
				pairs, err := splitStringToPairs(fmt.Sprintf("%v", match), options)
				if err != nil {
					return nil
				}
				parseKeyValuePairsResult, err := parseKeyValuePairs(pairs, strings.TrimSpace(options.SeparatorStr))
				if err != nil {
					return nil
				}
				return parseKeyValuePairsResult
			case "scale":
				functionArgsNumber, err := parseStringToNumber(args[0])
				if err != nil {
					return nil
				}
				matchNumber, err := parseStringToNumber(fmt.Sprintf("%v", match))
				if err != nil {
					return nil
				}
				switch functionArgsNumber := functionArgsNumber.(type) {
				case int64:
					switch matchNumber := matchNumber.(type) {
					case int64:
						return matchNumber * functionArgsNumber
					case float64:
						return matchNumber * float64(functionArgsNumber)
					}
				case float64:
					switch matchNumber := matchNumber.(type) {
					case int64:
						return float64(matchNumber) * functionArgsNumber
					case float64:
						return matchNumber * functionArgsNumber
					}
				}
				return nil
			}
		}
		return nil
	}
}

func splitByColonOutsideParentheses(input string) []string {
	var result []string
	var currentPart strings.Builder
	parenCount := 0
	inQuotes := false

	for i := 0; i < len(input); i++ {
		char := rune(input[i])

		// Handle escape sequences
		if char == '\\' && i+1 < len(input) {
			nextChar := rune(input[i+1])
			// If escaping a quote or another backslash, add both characters
			if nextChar == '"' || nextChar == '\\' {
				currentPart.WriteRune(char)
				currentPart.WriteRune(nextChar)
				i++ // Skip the next character as we've already handled it
				continue
			}
		}

		if char == '(' && !inQuotes {
			parenCount++
			currentPart.WriteRune(char)
		} else if char == ')' && !inQuotes {
			parenCount--
			currentPart.WriteRune(char)
		} else if char == '"' {
			// Only toggle quotes if it's not an escaped quote
			// (We already handled escaped quotes in the escape sequence check)
			inQuotes = !inQuotes
			currentPart.WriteRune(char)
		} else if char == ':' && parenCount == 0 && !inQuotes {
			// Found a colon outside of parentheses and quotes
			result = append(result, currentPart.String())
			currentPart.Reset()
		} else {
			currentPart.WriteRune(char)
		}
	}

	// Add the last part
	if currentPart.Len() > 0 {
		result = append(result, currentPart.String())
	}

	return result
}

// expand processes a pattern and returns expanded regular expression, type hints and error
func (grok *Grok) expand(pattern string, namedCapturesOnly bool) (string, map[string][]string, error) {
	hints := make(map[string][]string)
	expandedPattern := pattern

	// recursion break is guarding against cyclic reference in pattern definitions
	// as this is performed only once at compile time more clever optimization (e.g detecting cycles in graph) is TBD
	for recursionBreak := 1000; recursionBreak > 0; recursionBreak-- {
		subMatches := reusePattern.FindAllStringSubmatch(expandedPattern, -1)
		if len(subMatches) == 0 {
			// nothing to expand anymore
			break
		}

		for _, nameSubmatch := range subMatches {
			// grok can be specified in either of these forms:
			// %{SYNTAX} - e.g {NUMBER}
			// %{SYNTAX:ID} - e.g {NUMBER:MY_AGE}
			// %{SYNTAX:ID:TYPE} - e.g {NUMBER:MY_AGE:INT}

			// nameSubmatch is equal to [["%{NAME:ID:TYPe}" "NAME:ID:TYPe"]]
			// we need only inner part
			nameParts := splitByColonOutsideParentheses(nameSubmatch[1])

			grokId := nameParts[0]
			// replace grokId with default pattern if it exists
			if _, ok := patternDefaultsMappings[grokId]; ok {
				grokId = patternDefaultsMappings[grokId]
			}
			var targetId string
			if len(nameParts) > 1 {
				if nameParts[1] == "" {
					if len(nameParts) == 3 && (strings.HasPrefix(nameParts[2], "json") || strings.HasPrefix(nameParts[2], "keyvalue") || strings.HasPrefix(nameParts[2], "rubyhash")) {
						targetId = FlatToRoot
					} else {
						return "", nil, fmt.Errorf("target id is empty: %w", ErrParseFailure)
					}
				} else {
					targetId = strings.ReplaceAll(nameParts[1], ".", dotSep)
				}
			} else {
				targetId = grokId
			}
			if len(nameParts) > 1 {
				switch {
				case grokId == "NUMBER" && nameParts[0] != "numberStr":
					hints[targetId] = append(hints[targetId], "double")
				case (grokId == "INT" || grokId == "INTEGER") && nameParts[0] != "integerStr":
					hints[targetId] = append(hints[targetId], "int")
				}
			}
			// compile hints for used patterns
			if len(nameParts) == 3 {
				hints[targetId] = append(hints[targetId], nameParts[2])
			}

			knownPattern, found, lookupHint := grok.lookupPattern(grokId)
			if !found {
				return "", nil, fmt.Errorf("pattern definition %q unknown: %w", grokId, ErrParseFailure)
			}

			if lookupHint != "" {
				hints[targetId] = append(hints[targetId], lookupHint)
			}

			var replacementPattern string
			if namedCapturesOnly && len(nameParts) == 1 {
				// this has no semantic (pattern:foo) so we don't need to capture
				replacementPattern = "(" + knownPattern + ")"

			} else {
				replacementPattern = "(?P<" + targetId + ">" + knownPattern + ")"
			}

			// expand pattern with definition
			expandedPattern = strings.ReplaceAll(expandedPattern, nameSubmatch[0], replacementPattern)
		}
	}

	return expandedPattern, hints, nil
}

func createRegexPatternFromFormat(format string) (string, string) {
	// Handle quoted text (literals)
	formattedPattern := strings.Replace(format, "'T'", "T", -1)
	formattedPattern = strings.Replace(formattedPattern, "'", "", -1)

	// Perform replacements using token-based approach
	tokens := tokenizeFormat(formattedPattern)
	regexTokens := make([]string, len(tokens))
	copy(regexTokens, tokens)

	// Create a copy of the original format for Go format conversion
	goFormatTokens := make([]string, len(tokens))
	copy(goFormatTokens, tokens)

	// Apply regex replacements
	for i, token := range regexTokens {
		for _, r := range dateReplacements {
			if token == r.pattern {
				regexTokens[i] = r.regex
				break
			}
		}
	}

	// Apply Go format replacements
	for i, token := range goFormatTokens {
		for _, r := range dateReplacements {
			if token == r.pattern {
				goFormatTokens[i] = r.goTimeFormat
				break
			}
		}
	}

	return strings.Join(regexTokens, ""), strings.Join(goFormatTokens, "")
}

// Helper function to tokenize the format string
func tokenizeFormat(format string) []string {
	// Define all possible tokens in order of longest first
	possibleTokens := []string{
		"YYYY", "yyyy", "MMMM", "SSSSSS", "SSSSSSS", "EEE",
		"yyy", "MMM", "SSS",
		"yy", "MM", "DD", "dd", "HH", "hh", "mm", "ss", "ZZ",
		"y", "M", "d", "K", "H", "h", "m", "s", "Z", "z", "A", "a",
	}

	var tokens []string
	remaining := format

	for len(remaining) > 0 {
		matched := false

		// Try to match a token at the current position
		for _, token := range possibleTokens {
			if strings.HasPrefix(remaining, token) {
				tokens = append(tokens, token)
				remaining = remaining[len(token):]
				matched = true
				break
			}
		}

		// If no token matched, add the current character as a literal
		if !matched {
			tokens = append(tokens, string(remaining[0]))
			remaining = remaining[1:]
		}
	}

	return tokens
}

func (grok *Grok) lookupPattern(grokId string) (string, bool, string) {
	if knownPattern, found := grok.patternDefinitions[grokId]; found {
		return knownPattern, found, ""
	}

	if grok.lookupDefaultPatterns {
		if knownPattern, found := patterns.Default[grokId]; found {
			return knownPattern, found, ""
		}
	}

	parseResult := parseFunction(grokId)
	if parseResult != nil {
		functionName := parseResult.Name
		args := parseResult.Args
		switch functionName {
		case "date":
			if len(args) == 0 {
				return "", false, ""
			}
			regexPattern, goFormat := createRegexPatternFromFormat(unquoteString(args[0]))
			dateHint := fmt.Sprintf(`dateformat("%s")`, goFormat)
			if len(args) == 2 {
				dateHint = fmt.Sprintf(`dateformat("%s", "%s")`, goFormat, unquoteString(args[1]))
			}
			return regexPattern, true, dateHint
		case "regex":
			return strings.ReplaceAll(unquoteString(args[0]), `\\`, `\`), true, ""
		}
	}

	return "", false, ""
}
