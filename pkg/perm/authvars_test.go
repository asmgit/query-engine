package perm

import (
	"context"
	"testing"

	"github.com/hugr-lab/query-engine/pkg/auth"
)

func TestAuthVars_CustomClaims(t *testing.T) {
	ctx := auth.ContextWithAuthInfo(context.Background(), &auth.AuthInfo{
		Role:   "landlord_admin",
		UserId: "user1",
		Claims: map[string]any{"agency_id": "42", "role": "spoofed"},
	})

	vars := AuthVars(ctx)

	if got := vars["[$auth.agency_id]"]; got != "42" {
		t.Errorf("[$auth.agency_id] = %v, want 42", got)
	}
	if got := vars["[$auth.role]"]; got != "landlord_admin" {
		t.Errorf("[$auth.role] = %v, want landlord_admin (built-in must not be shadowed by raw claim)", got)
	}
}
