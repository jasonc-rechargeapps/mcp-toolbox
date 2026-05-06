// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package masking

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/googleapis/mcp-toolbox/internal/embeddingmodels"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/tools"
	"github.com/googleapis/mcp-toolbox/internal/util"
	"github.com/googleapis/mcp-toolbox/internal/util/parameters"
)

// Mask defines a single PII masking rule: values in the named field that match
// Pattern (a Go regular expression) are replaced with Replacement.
type Mask struct {
	Field       string `yaml:"field"       json:"field"`
	Pattern     string `yaml:"pattern"     json:"pattern"`
	Replacement string `yaml:"replacement" json:"replacement"`
}

// compiledMask is a Mask with Field and Pattern pre-compiled as *regexp.Regexp.
// Field is wrapped in ^(?:...)$ so plain names match exactly while regex
// patterns like .*_token match all fields with that suffix.
type compiledMask struct {
	fieldRe     *regexp.Regexp
	re          *regexp.Regexp
	replacement string
}

func compile(masks []Mask) ([]compiledMask, error) {
	out := make([]compiledMask, len(masks))
	for i, m := range masks {
		fieldRe, err := regexp.Compile("^(?:" + m.Field + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid mask field %q: %w", m.Field, err)
		}
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid mask pattern for field %q: %w", m.Field, err)
		}
		out[i] = compiledMask{fieldRe: fieldRe, re: re, replacement: m.Replacement}
	}
	return out, nil
}

// apply walks result through a JSON round-trip so that custom types (e.g.
// orderedmap.Row) become standard map[string]any, then redacts matching fields.
func apply(result any, masks []compiledMask) any {
	if len(masks) == 0 {
		return result
	}
	b, err := json.Marshal(result)
	if err != nil {
		return result
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return result
	}
	return applyToValue(generic, masks)
}

func applyToValue(v any, masks []compiledMask) any {
	switch val := v.(type) {
	case []any:
		for i, item := range val {
			val[i] = applyToValue(item, masks)
		}
		return val
	case map[string]any:
		for key, fieldVal := range val {
			// Recurse into nested structures first.
			fieldVal = applyToValue(fieldVal, masks)

			for _, m := range masks {
				if m.fieldRe.MatchString(key) {
					switch s := fieldVal.(type) {
					case string:
						fieldVal = m.re.ReplaceAllString(s, m.replacement)
					default:
						if m.re.MatchString(fmt.Sprintf("%v", fieldVal)) {
							fieldVal = m.replacement
						}
					}
				}
			}
			val[key] = fieldVal
		}
		return val
	default:
		return v
	}
}

// MaskedToolConfig wraps a ToolConfig and injects PII masking into the tool
// it produces. When masks is empty, Initialize returns the inner tool unchanged.
type MaskedToolConfig struct {
	inner tools.ToolConfig
	masks []compiledMask
}

// NewMaskedToolConfig compiles the mask patterns and returns a MaskedToolConfig.
// If masks is empty, inner is returned as-is (no allocation).
func NewMaskedToolConfig(inner tools.ToolConfig, masks []Mask) (tools.ToolConfig, error) {
	if len(masks) == 0 {
		return inner, nil
	}
	compiled, err := compile(masks)
	if err != nil {
		return nil, err
	}
	return MaskedToolConfig{inner: inner, masks: compiled}, nil
}

func (c MaskedToolConfig) ToolConfigType() string {
	return c.inner.ToolConfigType()
}

func (c MaskedToolConfig) Initialize(srcs map[string]sources.Source) (tools.Tool, error) {
	t, err := c.inner.Initialize(srcs)
	if err != nil {
		return nil, err
	}
	return &MaskedTool{inner: t, masks: c.masks}, nil
}

// MaskedTool delegates all Tool methods to inner, applying PII masks to Invoke
// results before returning them.
type MaskedTool struct {
	inner tools.Tool
	masks []compiledMask
}

var _ tools.Tool = &MaskedTool{}

func (t *MaskedTool) Invoke(ctx context.Context, rp tools.SourceProvider, params parameters.ParamValues, token tools.AccessToken) (any, util.ToolboxError) {
	result, err := t.inner.Invoke(ctx, rp, params, token)
	if err != nil {
		return nil, err
	}
	return apply(result, t.masks), nil
}

func (t *MaskedTool) EmbedParams(ctx context.Context, params parameters.ParamValues, models map[string]embeddingmodels.EmbeddingModel) (parameters.ParamValues, error) {
	return t.inner.EmbedParams(ctx, params, models)
}

func (t *MaskedTool) Manifest() tools.Manifest       { return t.inner.Manifest() }
func (t *MaskedTool) McpManifest() tools.McpManifest { return t.inner.McpManifest() }
func (t *MaskedTool) Authorized(svcs []string) bool  { return t.inner.Authorized(svcs) }

func (t *MaskedTool) RequiresClientAuthorization(sp tools.SourceProvider) (bool, error) {
	return t.inner.RequiresClientAuthorization(sp)
}

func (t *MaskedTool) ToConfig() tools.ToolConfig { return t.inner.ToConfig() }

func (t *MaskedTool) GetAuthTokenHeaderName(sp tools.SourceProvider) (string, error) {
	return t.inner.GetAuthTokenHeaderName(sp)
}

func (t *MaskedTool) GetParameters() parameters.Parameters { return t.inner.GetParameters() }
