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
