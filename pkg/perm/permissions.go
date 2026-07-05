package perm

import (
	"context"
	"fmt"
	"strconv"

	"github.com/vektah/gqlparser/v2/ast"

	"github.com/hugr-lab/query-engine/pkg/auth"
	"github.com/hugr-lab/query-engine/pkg/engines"
	"github.com/hugr-lab/query-engine/pkg/catalog/compiler/base"
	"github.com/hugr-lab/query-engine/pkg/catalog/sdl"
)

type RolePermissions struct {
	Name           string       `json:"name"`
	Disabled       bool         `json:"disabled"`
	CanImpersonate bool         `json:"can_impersonate"`
	Permissions    []Permission `json:"permissions"`
}

type Permission struct {
	Object   string         `json:"type_name"`
	Field    string         `json:"field_name"`
	Hidden   bool           `json:"hidden"`
	Disabled bool           `json:"disabled"`
	Filter   map[string]any `json:"filter"`
	Data     map[string]any `json:"data"`
}

func (r *RolePermissions) Enabled(object, field string) (*Permission, bool) {
	return r.checkObjectField(object, field, false)
}

func (r *RolePermissions) Visible(object, field string) (*Permission, bool) {
	return r.checkObjectField(object, field, true)
}

func (r *RolePermissions) CheckQuery(query *ast.Field) error {
	if r.Disabled {
		return auth.ErrForbidden
	}
	_, ok := r.Enabled(query.ObjectDefinition.Name, query.Name)
	if !ok {
		return auth.ErrForbidden
	}
	for _, f := range engines.SelectedFields(query.SelectionSet) {
		if err := r.CheckQuery(f.Field); err != nil {
			return err
		}
	}

	return nil
}


func (r *RolePermissions) CheckMutationInput(ctx context.Context, defs base.DefinitionsSource, inputName string, data map[string]any) error {
	if r.Disabled {
		return auth.ErrForbidden
	}
	if sdl.IsScalarType(inputName) {
		return nil
	}
	input := defs.ForName(ctx, inputName)
	if input == nil {
		return fmt.Errorf("input type %s not found", inputName)
	}
	for fn, fv := range data {
		if _, ok := r.Enabled(inputName, fn); !ok {
			return auth.ErrForbidden
		}
		if data, ok := fv.(map[string]any); ok {
			fd := input.Fields.ForName(fn)
			if fd == nil {
				return fmt.Errorf("field %s not found in input type %s", fn, inputName)
			}
			if err := r.CheckMutationInput(ctx, defs, fd.Type.Name(), data); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *RolePermissions) FilterArgument(ctx context.Context, object, field string) map[string]any {
	if r.Disabled {
		return nil
	}
	for _, p := range r.Permissions {
		if p.Object == object && p.Field == field {
			return applyContextVariable(ctx, p.Filter, nil)
		}
	}
	return nil
}

func (r *RolePermissions) DataArgument(ctx context.Context, object, field string) map[string]any {
	if r.Disabled {
		return nil
	}
	for _, p := range r.Permissions {
		if p.Object == object && p.Field == field {
			return applyContextVariable(ctx, p.Data, nil)
		}
	}
	return nil
}

// checkObjectField resolves the effective permission for (object, field) by
// most-specific-match, per the documented precedence:
//
//	exact (object, field) > (object, "*") > ("*", field) > ("*", "*") > open by default
//
// A more specific rule always overrides a less specific one, regardless of the
// order rows are stored in.
func (r *RolePermissions) checkObjectField(object, field string, toVisible bool) (*Permission, bool) {
	if r.Disabled {
		return nil, false
	}
	var best *Permission
	bestRank := -1
	for i := range r.Permissions {
		p := &r.Permissions[i]
		rank := -1
		switch {
		case p.Object == object && p.Field == field:
			rank = 3
		case p.Object == object && p.Field == "*":
			rank = 2
		case p.Object == "*" && p.Field == field:
			rank = 1
		case p.Object == "*" && p.Field == "*":
			rank = 0
		}
		if rank > bestRank {
			bestRank, best = rank, p
		}
	}
	if best == nil {
		return nil, true
	}
	out := best.Disabled
	if toVisible {
		out = best.Hidden
	}
	// Only an exact match carries a permission (its filter/data) back to the
	// caller; wildcard matches gate access without a concrete rule payload.
	if bestRank == 3 {
		return best, !out
	}
	return nil, !out
}

func applyContextVariable(ctx context.Context, data map[string]any, vars map[string]any) map[string]any {
	if len(data) == 0 {
		return nil
	}
	if vars == nil {
		vars = AuthVars(ctx)
		if len(vars) == 0 {
			return data
		}
	}
	res := make(map[string]any, len(data))
	for k, v := range data {
		switch v := v.(type) {
		case map[string]any:
			res[k] = applyContextVariable(ctx, v, vars)
		case []any:
			for i, vv := range v {
				switch vv := vv.(type) {
				case map[string]any:
					v[i] = applyContextVariable(ctx, vv, vars)
				}
			}
		case string:
			if val, ok := vars[v]; ok {
				res[k] = val
				continue
			}
		}
	}

	return res
}

func AuthVars(ctx context.Context) map[string]any {
	ai := auth.AuthInfoFromContext(ctx)
	if ai == nil {
		return nil
	}

	userIdInt, _ := strconv.Atoi(ai.UserId)

	vars := map[string]any{
		"[$auth.user_name]":   ai.UserName,
		"[$auth.user_id]":     ai.UserId,
		"[$auth.user_id_int]": userIdInt,
		"[$auth.role]":        ai.Role,
		"[$auth.auth_type]":   ai.AuthType,
		"[$auth.provider]":    ai.AuthProvider,
	}
	if ai.ImpersonatedBy != nil {
		vars["[$auth.impersonated_by_role]"] = ai.ImpersonatedBy.Role
		vars["[$auth.impersonated_by_user_id]"] = ai.ImpersonatedBy.UserId
		vars["[$auth.impersonated_by_user_name]"] = ai.ImpersonatedBy.UserName
	}
	return vars
}
