package audit

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type patternFile struct {
	Patterns []patternEntry `yaml:"patterns"`
}

type patternEntry struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

// LoadPatterns reads a YAML file of custom redaction patterns and returns
// compiled NamedPatterns. The file format is:
//
//	patterns:
//	  - name: my-secret
//	    pattern: 'MY_SECRET_[A-Z0-9]+'
func LoadPatterns(path string) ([]NamedPattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var pf patternFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]NamedPattern, 0, len(pf.Patterns))
	for i, p := range pf.Patterns {
		if p.Name == "" {
			return nil, fmt.Errorf("pattern %d: name is required", i)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: invalid regex: %w", p.Name, err)
		}
		out = append(out, NamedPattern{Name: p.Name, Re: re})
	}
	return out, nil
}
