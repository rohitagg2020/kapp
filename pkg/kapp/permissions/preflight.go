// Copyright 2024 The Carvel Authors.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	cmdcore "carvel.dev/kapp/pkg/kapp/cmd/core"
	ctldgraph "carvel.dev/kapp/pkg/kapp/diffgraph"
	"carvel.dev/kapp/pkg/kapp/preflight"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Preflight is an implementation of preflight.Check
// to make it easier to add permission validation
// as a preflight check
type Preflight struct {
	depsFactory cmdcore.DepsFactory
	enabled     bool
	config      *PreflightConfig
}

const (
	PermissionValidatorTypeSelfSubjectAccessReview = "SelfSubjectAccessReview"
	PermissionValidatorTypeSelfSubjectRulesReview  = "SelfSubjectRulesReview"
)

type PreflightConfig struct {
	PermissionValidatorResource string `json:"permissionValidatorResource"`
}

func NewPreflight(depsFactory cmdcore.DepsFactory, enabled bool) preflight.Check {
	return &Preflight{
		depsFactory: depsFactory,
		enabled:     enabled,
		config: &PreflightConfig{
			PermissionValidatorResource: PermissionValidatorTypeSelfSubjectAccessReview,
		},
	}
}

func (p *Preflight) Enabled() bool {
	return p.enabled
}

func (p *Preflight) SetEnabled(enabled bool) {
	p.enabled = enabled
}

func (p *Preflight) SetConfig(cfg preflight.CheckConfig) error {
	pCfg := &PreflightConfig{}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("converting CheckConfig to bytes: %w", err)
	}

	err = json.Unmarshal(cfgBytes, pCfg)
	if err != nil {
		return fmt.Errorf("parsing permissions preflight config: %w", err)
	}

	switch pCfg.PermissionValidatorResource {
	// Valid, do nothing
	case PermissionValidatorTypeSelfSubjectAccessReview, PermissionValidatorTypeSelfSubjectRulesReview:
	// Default to using SelfSubjectAccessReview
	case "":
		pCfg.PermissionValidatorResource = PermissionValidatorTypeSelfSubjectAccessReview
	default:
		return fmt.Errorf("unknown permissionValidatorType %q", pCfg.PermissionValidatorResource)
	}
	return nil
}

func (p *Preflight) Run(ctx context.Context, changeGraph *ctldgraph.ChangeGraph) error {
	client, err := p.depsFactory.CoreClient()
	if err != nil {
		return err
	}

	mapper, err := p.depsFactory.RESTMapper()
	if err != nil {
		return err
	}

	var permissionValidator PermissionValidator
	switch p.config.PermissionValidatorResource {
	case PermissionValidatorTypeSelfSubjectAccessReview:
		permissionValidator = NewSelfSubjectAccessReviewValidator(client.AuthorizationV1().SelfSubjectAccessReviews())
	case PermissionValidatorTypeSelfSubjectRulesReview:
		permissionValidator = NewSelfSubjectRulesReviewValidator(client.AuthorizationV1().SelfSubjectRulesReviews())
	}

	roleValidator := NewRoleValidator(permissionValidator, mapper)
	bindingValidator := NewBindingValidator(permissionValidator, client.RbacV1(), mapper)
	basicValidator := NewBasicValidator(permissionValidator, mapper)

	validator := NewCompositeValidator(basicValidator, map[schema.GroupVersionKind]Validator{
		rbacv1.SchemeGroupVersion.WithKind("Role"):               roleValidator,
		rbacv1.SchemeGroupVersion.WithKind("ClusterRole"):        roleValidator,
		rbacv1.SchemeGroupVersion.WithKind("RoleBinding"):        bindingValidator,
		rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding"): bindingValidator,
	})

	errorSet := []error{}
	for _, change := range changeGraph.All() {
		switch change.Change.Op() {
		case ctldgraph.ActualChangeOpDelete:
			err = validator.Validate(ctx, change.Change.Resource(), "delete")
			if err != nil {
				errorSet = append(errorSet, err)
			}
		case ctldgraph.ActualChangeOpUpsert:
			// Check both create and update permissions
			err = validator.Validate(ctx, change.Change.Resource(), "create")
			if err != nil {
				errorSet = append(errorSet, err)
			}

			err = validator.Validate(ctx, change.Change.Resource(), "update")
			if err != nil {
				errorSet = append(errorSet, err)
			}
		}
	}

	if len(errorSet) > 0 {
		return errors.Join(errorSet...)
	}

	return nil
}
