package perm

import "testing"

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
