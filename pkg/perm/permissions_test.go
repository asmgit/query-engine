package perm

import (
	"context"
	"reflect"
	"testing"

	"github.com/hugr-lab/query-engine/pkg/auth"
)

func authCtx() context.Context {
	return auth.ContextWithAuthInfo(context.Background(), &auth.AuthInfo{
		Role:   "svc",
		UserId: "2",
	})
}

func TestApplyContextVariable_SubstitutesPlaceholder(t *testing.T) {
	got := applyContextVariable(authCtx(), map[string]any{
		"agency_id": map[string]any{"eq": "[$auth.user_id_int]"},
	}, nil)
	inner, _ := got["agency_id"].(map[string]any)
	if inner["eq"] != 2 {
		t.Fatalf("placeholder not substituted: got %#v", got)
	}
}

func TestApplyContextVariable_KeepsIntLiteral(t *testing.T) {
	got := applyContextVariable(authCtx(), map[string]any{
		"agency_id": map[string]any{"eq": 2},
	}, nil)
	inner, _ := got["agency_id"].(map[string]any)
	if inner["eq"] != 2 {
		t.Fatalf("int literal dropped: got %#v", got)
	}
}

func TestApplyContextVariable_KeepsStringLiteral(t *testing.T) {
	got := applyContextVariable(authCtx(), map[string]any{
		"status": map[string]any{"eq": "pending"},
	}, nil)
	inner, _ := got["status"].(map[string]any)
	if inner["eq"] != "pending" {
		t.Fatalf("string literal dropped: got %#v", got)
	}
}

func TestApplyContextVariable_KeepsListOperatorAndSubstitutesInside(t *testing.T) {
	got := applyContextVariable(authCtx(), map[string]any{
		"_or": []any{
			map[string]any{"agency_id": map[string]any{"eq": "[$auth.user_id_int]"}},
			map[string]any{"building_id": map[string]any{"gt": 5}},
		},
	}, nil)
	list, ok := got["_or"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("_or branch dropped: got %#v", got)
	}
	first, _ := list[0].(map[string]any)
	agency, _ := first["agency_id"].(map[string]any)
	if agency["eq"] != 2 {
		t.Fatalf("placeholder inside _or not substituted: got %#v", list[0])
	}
	second, _ := list[1].(map[string]any)
	building, _ := second["building_id"].(map[string]any)
	if building["gt"] != 5 {
		t.Fatalf("literal inside _or dropped: got %#v", list[1])
	}
}

func TestApplyContextVariable_NoAuthReturnsUnchanged(t *testing.T) {
	data := map[string]any{"agency_id": map[string]any{"eq": 2}}
	got := applyContextVariable(context.Background(), data, nil)
	inner, _ := got["agency_id"].(map[string]any)
	if inner["eq"] != 2 {
		t.Fatalf("unchanged path lost literal: got %#v", got)
	}
	if !reflect.DeepEqual(got, data) {
		t.Fatalf("expected data returned unchanged, got %#v", got)
	}
}

func en(object, field string, disabled bool) Permission {
	return Permission{Object: object, Field: field, Disabled: disabled}
}

func TestCheckObjectField_Precedence(t *testing.T) {
	tests := []struct {
		name  string
		perms []Permission
		want  bool
	}{
		{"open by default", nil, true},
		{"exact deny", []Permission{en("users", "email", true)}, false},
		{"per-type wildcard deny", []Permission{en("users", "*", true)}, false},
		{"per-type wildcard allow other type", []Permission{en("orders", "*", true)}, true},
		{"global deny", []Permission{en("*", "*", true)}, false},
		{"global deny + exact allow", []Permission{en("*", "*", true), en("users", "email", false)}, true},
		{"global deny + per-type allow", []Permission{en("*", "*", true), en("users", "*", false)}, true},
		{"per-type deny + exact allow", []Permission{en("users", "*", true), en("users", "email", false)}, true},
		{"per-type allow + exact deny", []Permission{en("users", "*", false), en("users", "email", true)}, false},
		{"field wildcard deny", []Permission{en("*", "email", true)}, false},
		{"order independence", []Permission{en("users", "email", false), en("users", "*", true), en("*", "*", true)}, true},
	}
	for _, tt := range tests {
		r := &RolePermissions{Permissions: tt.perms}
		if _, ok := r.Enabled("users", "email"); ok != tt.want {
			t.Errorf("%s: Enabled = %v, want %v", tt.name, ok, tt.want)
		}
	}
}

func TestCheckObjectField_DisabledRole(t *testing.T) {
	r := &RolePermissions{Disabled: true}
	if _, ok := r.Enabled("users", "email"); ok {
		t.Error("disabled role must deny everything")
	}
}
