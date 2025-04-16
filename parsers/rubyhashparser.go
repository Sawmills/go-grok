package parsers

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// RubyHashParser parses Ruby hash syntax into Go map structures
type RubyHashParser struct{}

// Parse converts a Ruby hash string to a Go map
func (p *RubyHashParser) Parse(input string) (map[string]interface{}, error) {
	// Trim leading/trailing whitespace
	input = strings.TrimSpace(input)

	// Check if it starts with a symbol syntax like {:symbol=>value}
	if strings.HasPrefix(input, "{:") {
		return p.parseRubyHash(input)
	} else if strings.HasPrefix(input, "{") && strings.HasSuffix(input, "}") {
		return p.parseRubyHash(input)
	}

	return nil, errors.New("input must be enclosed in braces {}")
}

// parseRubyHash parses a Ruby hash string into a Go map
func (p *RubyHashParser) parseRubyHash(input string) (map[string]interface{}, error) {
	// Trim the outer braces
	if !strings.HasPrefix(input, "{") || !strings.HasSuffix(input, "}") {
		return nil, errors.New("input must be enclosed in braces {}")
	}

	content := input[1 : len(input)-1]
	if len(content) == 0 {
		// Empty hash
		return make(map[string]interface{}), nil
	}

	// Result map
	result := make(map[string]interface{})

	// Process the content
	pos := 0
	for pos < len(content) {
		// Skip whitespace
		pos = p.skipWhitespace(content, pos)
		if pos >= len(content) {
			break
		}

		// Parse the key
		key, newPos, err := p.parseKey(content, pos)
		if err != nil {
			return nil, fmt.Errorf("key parse error at position %d: %w", pos, err)
		}
		pos = newPos

		// Skip whitespace
		pos = p.skipWhitespace(content, pos)

		// Expect =>
		if pos+1 >= len(content) || content[pos:pos+2] != "=>" {
			return nil, fmt.Errorf("expected => at position %d", pos)
		}
		pos += 2

		// Skip whitespace
		pos = p.skipWhitespace(content, pos)

		// Parse the value
		value, newPos, err := p.parseValue(content, pos)
		if err != nil {
			return nil, fmt.Errorf("value parse error at position %d: %w", pos, err)
		}
		pos = newPos

		// Add to result
		result[key] = value

		// Skip whitespace
		pos = p.skipWhitespace(content, pos)

		// If there's a comma, skip it
		if pos < len(content) && content[pos] == ',' {
			pos++
		}
	}

	return result, nil
}

// skipWhitespace advances the position past any whitespace
func (p *RubyHashParser) skipWhitespace(s string, pos int) int {
	for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r') {
		pos++
	}
	return pos
}

// parseKey extracts a key (which could be a bareword, symbol, or a string)
func (p *RubyHashParser) parseKey(s string, pos int) (string, int, error) {
	if pos >= len(s) {
		return "", pos, errors.New("unexpected end of input while parsing key")
	}

	// Check for symbol syntax (:symbol)
	if s[pos] == ':' {
		// Symbol key
		pos++ // Skip the colon
		start := pos
		for pos < len(s) && p.isIdentifierChar(s[pos]) {
			pos++
		}

		if start == pos {
			return "", pos, fmt.Errorf("empty symbol key at position %d", pos)
		}

		return s[start:pos], pos, nil
	}

	// If it's a quoted string
	if s[pos] == '"' || s[pos] == '\'' {
		return p.parseQuotedString(s, pos)
	}

	// Otherwise, it's a bareword
	start := pos
	for pos < len(s) && p.isIdentifierChar(s[pos]) {
		pos++
	}

	if start == pos {
		return "", pos, fmt.Errorf("empty key at position %d", pos)
	}

	return s[start:pos], pos, nil
}

// isIdentifierChar checks if a character is valid in an identifier
func (p *RubyHashParser) isIdentifierChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// parseQuotedString extracts a quoted string
func (p *RubyHashParser) parseQuotedString(s string, pos int) (string, int, error) {
	if pos >= len(s) {
		return "", pos, errors.New("unexpected end of input while parsing string")
	}

	quote := s[pos]
	pos++ // Skip the opening quote

	var value strings.Builder

	for pos < len(s) && s[pos] != quote {
		// Handle escaped characters
		if s[pos] == '\\' && pos+1 < len(s) {
			pos++ // Skip the backslash
			// Handle specific escape sequences
			if pos < len(s) {
				switch s[pos] {
				case 'n':
					value.WriteByte('\n')
				case 't':
					value.WriteByte('\t')
				case 'r':
					value.WriteByte('\r')
				default:
					// For other escapes, just add the character (handles \" \' \\ etc.)
					value.WriteByte(s[pos])
				}
			}
			pos++
			continue
		}

		// Regular character
		value.WriteByte(s[pos])
		pos++
	}

	if pos >= len(s) {
		return "", pos, errors.New("unterminated string")
	}

	pos++ // Skip the closing quote

	return value.String(), pos, nil
}

// parseValue extracts a value (string, number, boolean, nil, or nested hash)
func (p *RubyHashParser) parseValue(s string, pos int) (interface{}, int, error) {
	if pos >= len(s) {
		return nil, pos, errors.New("unexpected end of input while parsing value")
	}

	// Check for nested hash
	if s[pos] == '{' {
		// Find the matching closing brace
		start := pos
		end, err := p.findMatchingBrace(s, pos)
		if err != nil {
			return nil, pos, err
		}

		// Recursively parse the nested hash
		nestedHashStr := s[start : end+1]
		nestedHash, err := p.parseRubyHash(nestedHashStr)
		if err != nil {
			return nil, pos, err
		}

		return nestedHash, end + 1, nil
	}

	// Check for quoted string
	if s[pos] == '"' || s[pos] == '\'' {
		value, newPos, err := p.parseQuotedString(s, pos)
		if err != nil {
			return nil, pos, err
		}
		return value, newPos, nil
	}

	// Check for symbol
	if s[pos] == ':' {
		pos++ // Skip the colon
		start := pos
		for pos < len(s) && p.isIdentifierChar(s[pos]) {
			pos++
		}

		if start == pos {
			return "", pos, fmt.Errorf("empty symbol at position %d", pos)
		}

		return s[start:pos], pos, nil
	}

	// Check for arrays
	if s[pos] == '[' {
		return p.parseArray(s, pos)
	}

	// Check for other literals (numbers, booleans, nil)
	start := pos
	for pos < len(s) && !p.isTerminator(s[pos]) {
		pos++
	}

	if start == pos {
		return nil, pos, fmt.Errorf("empty value at position %d", pos)
	}

	literal := strings.TrimSpace(s[start:pos])

	// Convert to appropriate type
	switch literal {
	case "true":
		return true, pos, nil
	case "false":
		return false, pos, nil
	case "nil":
		return nil, pos, nil
	default:
		// Try to parse as number
		if p.isNumeric(literal) {
			if strings.Contains(literal, ".") {
				// Floating point
				var f float64
				_, err := fmt.Sscanf(literal, "%f", &f)
				if err == nil {
					return f, pos, nil
				}
			} else {
				// Integer
				var i int64
				_, err := fmt.Sscanf(literal, "%d", &i)
				if err == nil {
					return i, pos, nil
				}
			}
		}
		// Default to treating as string
		return literal, pos, nil
	}
}

// findMatchingBrace finds the position of the matching closing brace
func (p *RubyHashParser) findMatchingBrace(s string, start int) (int, error) {
	if start >= len(s) || s[start] != '{' {
		return -1, errors.New("expected opening brace")
	}

	braceCount := 1
	pos := start + 1
	inQuotes := false
	quoteChar := byte(0)

	for pos < len(s) && braceCount > 0 {
		// Handle quoted strings (skip their content)
		if (s[pos] == '"' || s[pos] == '\'') && (pos == 0 || s[pos-1] != '\\') {
			if !inQuotes {
				inQuotes = true
				quoteChar = s[pos]
			} else if s[pos] == quoteChar {
				inQuotes = false
			}
			pos++
			continue
		}

		// Skip content inside quotes
		if inQuotes {
			pos++
			continue
		}

		// Handle braces
		if s[pos] == '{' {
			braceCount++
		} else if s[pos] == '}' {
			braceCount--
		}

		pos++
	}

	if braceCount != 0 {
		return -1, errors.New("unmatched braces")
	}

	return pos - 1, nil // Position of the matching closing brace
}

// parseArray parses a Ruby array into a Go slice
func (p *RubyHashParser) parseArray(s string, start int) ([]interface{}, int, error) {
	if start >= len(s) || s[start] != '[' {
		return nil, start, errors.New("expected opening bracket for array")
	}

	pos := start + 1 // Skip the opening bracket
	result := make([]interface{}, 0)

	for pos < len(s) && s[pos] != ']' {
		// Skip whitespace
		pos = p.skipWhitespace(s, pos)
		if pos >= len(s) {
			return nil, start, errors.New("unterminated array")
		}

		// End of array?
		if s[pos] == ']' {
			break
		}

		// Parse value
		value, newPos, err := p.parseValue(s, pos)
		if err != nil {
			return nil, start, err
		}

		result = append(result, value)
		pos = newPos

		// Skip whitespace
		pos = p.skipWhitespace(s, pos)

		// Expect comma or end bracket
		if pos < len(s) && s[pos] == ',' {
			pos++ // Skip comma
		}
	}

	if pos >= len(s) || s[pos] != ']' {
		return nil, start, errors.New("unterminated array")
	}

	return result, pos + 1, nil // Skip the closing bracket
}

// isTerminator checks if a character would terminate a value
func (p *RubyHashParser) isTerminator(c byte) bool {
	return c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isNumeric checks if a string represents a number
func (p *RubyHashParser) isNumeric(s string) bool {
	// Match integers and floating point numbers
	re := regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	return re.MatchString(s)
}

func main() {
	// Example usage
	parser := &RubyHashParser{}

	// Example 1: Small hash
	smallHash := `{:path=>"/usr/share/logstash/vendor/bundle/jruby/2.3.0/gems/logstash-filter-geoip-5.0.3-java/vendor/GeoLite2-City.mmdb"}`
	result1, err := parser.Parse(smallHash)
	if err != nil {
		fmt.Println("Error parsing small hash:", err)
	} else {
		fmt.Println("Parsed small hash:", result1)
	}

	// Example 2: Nested hash
	nestedHash := `{name => "John", "job" => {"company" => "Big Company", "title" => "CTO"}}`
	result2, err := parser.Parse(nestedHash)
	if err != nil {
		fmt.Println("Error parsing nested hash:", err)
	} else {
		fmt.Println("Parsed nested hash:", result2)
	}

	// Example 3: Complex hash (truncated for clarity)
	complexHash := `{:status=>500, :request_method=>"GET", :path_info=>"/_node/stats", :error=>"Unexpected Internal Error"}`
	result3, err := parser.Parse(complexHash)
	if err != nil {
		fmt.Println("Error parsing complex hash:", err)
	} else {
		fmt.Println("Parsed complex hash:", result3)
	}
}
