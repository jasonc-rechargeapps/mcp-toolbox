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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/tools"
)

func compileMasks(t *testing.T, masks []Mask) []compiledMask {
	t.Helper()
	c, err := compile(masks)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

func TestApply_StringField(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "email", Pattern: `[^@]+@[^@]+`, Replacement: "***@***.***"},
	})
	input := []any{
		map[string]any{"id": float64(1), "email": "user@example.com"},
		map[string]any{"id": float64(2), "email": "admin@corp.io"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"id": float64(1), "email": "***@***.***"},
		map[string]any{"id": float64(2), "email": "***@***.***"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_SSNPattern(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "ssn", Pattern: `\d{3}-\d{2}-\d{4}`, Replacement: "XXX-XX-XXXX"},
	})
	input := []any{
		map[string]any{"name": "Alice", "ssn": "123-45-6789"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"name": "Alice", "ssn": "XXX-XX-XXXX"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_FieldNotPresent(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "secret", Pattern: `.*`, Replacement: "REDACTED"},
	})
	input := []any{
		map[string]any{"name": "Bob", "value": "safe"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"name": "Bob", "value": "safe"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_MultipleMasks(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "email", Pattern: `.+`, Replacement: "[email]"},
		{Field: "phone", Pattern: `.+`, Replacement: "[phone]"},
	})
	input := []any{
		map[string]any{"email": "x@y.com", "phone": "555-1234", "name": "Carol"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"email": "[email]", "phone": "[phone]", "name": "Carol"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_NoMasks(t *testing.T) {
	input := []any{map[string]any{"secret": "password"}}
	got := apply(input, nil)
	// With no masks, the original input is returned without modification.
	want := []any{map[string]any{"secret": "password"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_StringFieldMatchedByPattern(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "card_number", Pattern: `\d{16}`, Replacement: "REDACTED"},
	})
	input := []any{
		map[string]any{"card_number": "1234567890123456"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"card_number": "REDACTED"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_WildcardField(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: `.*_token`, Pattern: `.*`, Replacement: "[REDACTED]"},
	})
	input := []any{
		map[string]any{
			"stripe_customer_token":          "tok_stripe",
			"paypal_customer_token":          "tok_paypal",
			"authorizedotnet_customer_token": "tok_auth",
			"email":                          "user@example.com",
		},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{
			"stripe_customer_token":          "[REDACTED]",
			"paypal_customer_token":          "[REDACTED]",
			"authorizedotnet_customer_token": "[REDACTED]",
			"email":                          "user@example.com",
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_ExactFieldStillExact(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "token", Pattern: `.*`, Replacement: "[REDACTED]"},
	})
	input := []any{
		map[string]any{"token": "abc", "access_token": "should-not-match"},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{"token": "[REDACTED]", "access_token": "should-not-match"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_EmbeddedJSONString(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: "account_id", Pattern: `.*`, Replacement: "[REDACTED]"},
	})
	input := []any{
		map[string]any{
			"id":         float64(1),
			"json_field": `{"account_id":"000000099999999","cart_enabled":true}`,
		},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{
			"id":         float64(1),
			"json_field": `{"cart_enabled":true,"account_id":"[REDACTED]"}`,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestApply_EmbeddedJSONStringNestedObject(t *testing.T) {
	masks := compileMasks(t, []Mask{
		{Field: `.*_key`, Pattern: `.*`, Replacement: "[REDACTED]"},
	})
	input := []any{
		map[string]any{
			"id":         float64(1),
			"json_field": `{"aes_migration_token_data":{"api_key":"enc123","public_key":"enc456"},"cart_enabled":true}`,
		},
	}
	got := apply(input, masks)
	want := []any{
		map[string]any{
			"id":         float64(1),
			"json_field": `{"aes_migration_token_data":{"public_key":"[REDACTED]","api_key":"[REDACTED]"},"cart_enabled":true}`,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestCompile_InvalidPattern(t *testing.T) {
	_, err := compile([]Mask{
		{Field: "f", Pattern: `[invalid`, Replacement: "X"},
	})
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestCompile_InvalidFieldPattern(t *testing.T) {
	_, err := compile([]Mask{
		{Field: `[invalid_field`, Pattern: `.*`, Replacement: "X"},
	})
	if err == nil {
		t.Error("expected error for invalid field regex, got nil")
	}
}

func TestNewMaskedToolConfig_EmptyMasks(t *testing.T) {
	inner := &stubToolConfig{}
	got, err := NewMaskedToolConfig(inner, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != inner {
		t.Error("expected inner returned unchanged when masks is empty")
	}
}

func TestNewMaskedToolConfig_InvalidPattern(t *testing.T) {
	inner := &stubToolConfig{}
	_, err := NewMaskedToolConfig(inner, []Mask{
		{Field: "f", Pattern: `[bad`, Replacement: "X"},
	})
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

// stubToolConfig satisfies tools.ToolConfig for testing.
type stubToolConfig struct{}

func (s *stubToolConfig) ToolConfigType() string { return "stub" }
func (s *stubToolConfig) Initialize(_ map[string]sources.Source) (tools.Tool, error) {
	return nil, nil
}
