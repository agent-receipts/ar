package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// FileConfig is the subset of Config that can be set from the TOML config
// file. Every field mirrors an existing flag/env var so operators have one
// mental model: the TOML key is the flag name with dashes turned into
// underscores. Pointer-typed fields distinguish "absent in the file" (nil,
// so a lower-precedence default/env/flag wins) from "explicitly set to the
// zero value" (e.g. parameter_disclosure = false) — the config file is the
// lowest-priority layer, so an absent key must never clobber env or flags.
type FileConfig struct {
	Socket              *string `toml:"socket"`
	DB                  *string `toml:"db"`
	Key                 *string `toml:"key"`
	PublicKey           *string `toml:"public_key"`
	ChainID             *string `toml:"chain_id"`
	IssuerID            *string `toml:"issuer_id"`
	VerificationMethod  *string `toml:"verification_method"`
	ParameterDisclosure *bool   `toml:"parameter_disclosure"`
	RedactPatterns      *string `toml:"redact_patterns"`
	UnsafeSocketPath    *bool   `toml:"unsafe_socket_path"`
	// ShutdownDeadline accepts a Go duration string, e.g. "200ms" or "1s".
	ShutdownDeadline *Duration `toml:"shutdown_deadline"`
}

// Duration wraps time.Duration so it decodes from a TOML string such as
// "200ms" or "1s" via Go's time.ParseDuration. BurntSushi/toml has no native
// duration type; without this an operator would have to write nanoseconds.
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler so toml.DecodeFile parses
// a quoted duration string into a time.Duration. An empty string is rejected
// — a key present in the file but blank is a misconfiguration, not a default.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(text), err)
	}
	d.Duration = parsed
	return nil
}

// DefaultConfigPath returns the per-user TOML config path used when --config
// is not given: $XDG_DATA_HOME/agent-receipts/daemon.toml, co-located with
// receipts.db and the signing key (DefaultDBPath/DefaultKeyPath). Returns ""
// when the XDG data home cannot be resolved (no XDG_DATA_HOME and no home
// directory), matching the other Default*Path helpers.
func DefaultConfigPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "daemon.toml")
}

// LoadConfigFile reads and strictly decodes the TOML config at path.
//
//   - required=false (default-path load): a missing file is not an error —
//     it returns (nil, nil) so the daemon runs on flags/env alone. Any other
//     read or parse error is returned, because a present-but-broken config is
//     a misconfiguration we refuse to silently ignore.
//   - required=true (explicit --config): a missing file IS an error — the
//     operator named a path that does not exist, which is almost certainly a
//     typo rather than an intentional "no config".
//
// Unknown keys are rejected: a typo'd key (e.g. "sockett") would otherwise be
// silently ignored, leaving the daemon running with a different config than
// the operator believes they set. This mirrors the redact-pattern loader's
// "reject malformed config rather than silently degrade" stance.
func LoadConfigFile(path string, required bool) (*FileConfig, error) {
	if path == "" {
		return nil, errors.New("config path is empty")
	}
	var fc FileConfig
	md, err := toml.DecodeFile(path, &fc)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			return nil, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %s does not exist", path)
		}
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config %s: unknown key(s): %v", path, keys)
	}
	return &fc, nil
}

// configFileExists reports whether path exists as a regular file. Callers use
// it to log whether the default config was picked up; LoadConfigFile itself
// already tolerates a missing default-path file.
func configFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
