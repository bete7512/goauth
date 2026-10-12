package gorm

import (
	"fmt"
	"strings"
)

// This is a lexical splitter, not a SQL grammar. Client-side DELIMITER commands
// and unquoted procedural bodies require an external migration runner.
func splitSQLStatements(script string) ([]string, error) {
	var result []string
	start, quote, blockDepth := 0, byte(0), 0
	lineComment, hasSQL := false, false
	dollar := ""
	for i := 0; i < len(script); i++ {
		c := script[i]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			continue
		}
		if blockDepth > 0 {
			if strings.HasPrefix(script[i:], "/*") {
				blockDepth++
				i++
			} else if strings.HasPrefix(script[i:], "*/") {
				blockDepth--
				i++
			}
			continue
		}
		if dollar != "" {
			if strings.HasPrefix(script[i:], dollar) {
				i += len(dollar) - 1
				dollar = ""
			}
			continue
		}
		if quote != 0 {
			if c == '\\' && quote == '\'' && i+1 < len(script) {
				i++
				continue
			}
			if c == quote {
				if i+1 < len(script) && script[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if strings.HasPrefix(script[i:], "--") {
			lineComment = true
			i++
			continue
		}
		if strings.HasPrefix(script[i:], "/*") {
			blockDepth = 1
			i++
			continue
		}
		if c == ';' {
			if hasSQL {
				result = append(result, strings.TrimSpace(script[start:i]))
			}
			start, hasSQL = i+1, false
			continue
		}
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		hasSQL = true
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		if c == '$' {
			for j := i + 1; j < len(script); j++ {
				if script[j] == '$' {
					dollar = script[i : j+1]
					i = j
					break
				}
				d := script[j]
				if !((d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') || d == '_' || (j > i+1 && d >= '0' && d <= '9')) {
					break
				}
			}
		}
	}
	if quote != 0 || dollar != "" || blockDepth != 0 {
		return nil, fmt.Errorf("unterminated quoted SQL or comment in migration")
	}
	if hasSQL {
		result = append(result, strings.TrimSpace(script[start:]))
	}
	return result, nil
}
