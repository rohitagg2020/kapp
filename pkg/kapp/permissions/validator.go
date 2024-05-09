// Copyright 2024 The Carvel Authors.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"context"
	"errors"
	"fmt"
	"sync"

	ctlres "carvel.dev/kapp/pkg/kapp/resources"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	rbacv1client "k8s.io/client-go/kubernetes/typed/rbac/v1"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

type Validator interface {
	Validate(context.Context, ctlres.Resource, string) error
}

type PermissionValidator interface {
	ValidatePermissions(context.Context, *authv1.ResourceAttributes) error
}

// SelfSubjectAccessReviewValidator is for validating permissions via SelfSubjectAccessReview
type SelfSubjectAccessReviewValidator struct {
	ssarClient authv1client.SelfSubjectAccessReviewInterface
}

func NewSelfSubjectAccessReviewValidator(ssarClient authv1client.SelfSubjectAccessReviewInterface) *SelfSubjectAccessReviewValidator {
	return &SelfSubjectAccessReviewValidator{
		ssarClient: ssarClient,
	}
}

// ValidatePermissons will validate permissions for a ResourceAttributes object using SelfSubjectAccessReview.
// An error is returned if there are any issues creating a SelfSubjectAccessReview (i.e can't determine permissions)
// or if the SelfSubjectAccessReview is evaluated and the caller does not have the permission to perform the actions
// identified in the provided ResourceAttributes.
func (rv *SelfSubjectAccessReviewValidator) ValidatePermissions(ctx context.Context, resourceAttrib *authv1.ResourceAttributes) error {
	ssar := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: resourceAttrib,
		},
	}

	retSsar, err := rv.ssarClient.Create(ctx, ssar, v1.CreateOptions{})
	if err != nil {
		return err
	}

	if retSsar == nil {
		return errors.New("unable to validate permissions: returned SelfSubjectAccessReview is nil")
	}

	if retSsar.Status.EvaluationError != "" {
		return fmt.Errorf("unable to validate permissions: %s", retSsar.Status.EvaluationError)
	}

	if !retSsar.Status.Allowed {
		gvr := schema.GroupVersionResource{
			Group:    resourceAttrib.Group,
			Version:  resourceAttrib.Version,
			Resource: resourceAttrib.Resource,
		}
		return fmt.Errorf("not permitted to %q %s",
			resourceAttrib.Verb,
			gvr.String())
	}

	return nil
}

// SelfSubjectRulesReviewValidator is for validating permissions via SelfSubjectRulesReview
type SelfSubjectRulesReviewValidator struct {
	ssrrClient authv1client.SelfSubjectRulesReviewInterface
	cache      map[string][]rbacv1.PolicyRule
	mu         sync.Mutex
}

func NewSelfSubjectRulesReviewValidator(ssrrClient authv1client.SelfSubjectRulesReviewInterface) *SelfSubjectRulesReviewValidator {
	return &SelfSubjectRulesReviewValidator{
		ssrrClient: ssrrClient,
		cache:      make(map[string][]rbacv1.PolicyRule),
		mu:         sync.Mutex{},
	}
}

// ValidatePermissons will validate permissions for a ResourceAttributes object using SelfSubjectRulesReview.
// An error is returned if there are any issues creating a SelfSubjectRulesReview (i.e can't determine permissions)
// or if the SelfSubjectRulesReview is evaluated and the caller does not have the permission to perform the actions
// identified in the provided ResourceAttributes.
func (rv *SelfSubjectRulesReviewValidator) ValidatePermissions(ctx context.Context, resourceAttrib *authv1.ResourceAttributes) error {
	rv.mu.Lock()
	defer rv.mu.Unlock()

	ns := resourceAttrib.Namespace
	if ns == "" {
		ns = "default"
	}

	if _, ok := rv.cache[ns]; !ok {
		rules := []rbacv1.PolicyRule{}
		ssrr, err := rv.ssrrClient.Create(ctx,
			&authv1.SelfSubjectRulesReview{
				Spec: authv1.SelfSubjectRulesReviewSpec{
					Namespace: ns,
				},
			},
			v1.CreateOptions{},
		)
		if err != nil {
			return fmt.Errorf("creating selfsubjectrulesreview: %w", err)
		}
		if ssrr.Status.Incomplete {
			return errors.New("selfsubjectrulesreview is incomplete")
		}

		for _, rule := range ssrr.Status.ResourceRules {
			rules = append(rules, rbacv1.PolicyRule{
				Verbs:         rule.Verbs,
				APIGroups:     rule.APIGroups,
				Resources:     rule.Resources,
				ResourceNames: rule.ResourceNames,
			})
		}

		for _, rule := range ssrr.Status.NonResourceRules {
			rules = append(rules, rbacv1.PolicyRule{
				Verbs:           rule.Verbs,
				NonResourceURLs: rule.NonResourceURLs,
			})
		}

		rv.cache[ns] = rules
	}

	rules := rv.cache[ns]

	if !rbacauthorizer.RulesAllow(authorizer.AttributesRecord{
		Verb:            resourceAttrib.Verb,
		Name:            resourceAttrib.Name,
		Namespace:       resourceAttrib.Namespace,
		Resource:        resourceAttrib.Resource,
		APIGroup:        resourceAttrib.Group,
		ResourceRequest: true,
	}, rules...) {
		gvr := schema.GroupVersionResource{
			Group:    resourceAttrib.Group,
			Version:  resourceAttrib.Version,
			Resource: resourceAttrib.Resource,
		}
		return fmt.Errorf("not permitted to %q %s",
			resourceAttrib.Verb,
			gvr.String())
	}
	return nil
}

// RulesForRole will return a slice of rbacv1.PolicyRule objects
// that are representative of a provided (Cluster)Role's rules.
// It returns an error if one occurs during the process of fetching this
// information or if it is unable to determine the kind of binding this is
func RulesForRole(res ctlres.Resource) ([]rbacv1.PolicyRule, error) {
	switch res.Kind() {
	case "Role":
		role := &rbacv1.Role{}
		err := res.AsTypedObj(role)
		if err != nil {
			return nil, fmt.Errorf("converting resource to typed Role object: %w", err)
		}

		return role.Rules, nil

	case "ClusterRole":
		role := &rbacv1.ClusterRole{}
		err := res.AsTypedObj(role)
		if err != nil {
			return nil, fmt.Errorf("converting resource to typed ClusterRole object: %w", err)
		}

		return role.Rules, nil
	}

	return nil, fmt.Errorf("unknown role kind %q", res.Kind())
}

// RulesForBinding will return a slice of rbacv1.PolicyRule objects
// that are representative of the (Cluster)Role rules that a (Cluster)RoleBinding
// references. It returns an error if one occurs during the process of fetching this
// information or if it is unable to determine the kind of binding this is
func RulesForBinding(ctx context.Context, rbacClient rbacv1client.RbacV1Interface, res ctlres.Resource) ([]rbacv1.PolicyRule, error) {
	switch res.Kind() {
	case "RoleBinding":
		roleBinding := &rbacv1.RoleBinding{}
		err := res.AsTypedObj(roleBinding)
		if err != nil {
			return nil, fmt.Errorf("converting resource to typed RoleBinding object: %w", err)
		}

		return RulesForRoleBinding(ctx, rbacClient, roleBinding)
	case "ClusterRoleBinding":
		roleBinding := &rbacv1.ClusterRoleBinding{}
		err := res.AsTypedObj(roleBinding)
		if err != nil {
			return nil, fmt.Errorf("converting resource to typed ClusterRoleBinding object: %w", err)
		}

		return RulesForClusterRoleBinding(ctx, rbacClient, roleBinding)
	}

	return nil, fmt.Errorf("unknown binding kind %q", res.Kind())
}

// RulesForRoleBinding will return a slice of rbacv1.PolicyRule objects
// that are representative of the (Cluster)Role rules that a RoleBinding
// references. It returns an error if one occurs during the process of fetching this
// information.
func RulesForRoleBinding(ctx context.Context, rbacClient rbacv1client.RbacV1Interface, rb *rbacv1.RoleBinding) ([]rbacv1.PolicyRule, error) {
	switch rb.RoleRef.Kind {
	case "ClusterRole":
		role, err := rbacClient.ClusterRoles().Get(ctx, rb.RoleRef.Name, v1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("fetching ClusterRole %q for RoleBinding %q: %w", rb.RoleRef.Name, rb.Name, err)
		}

		return role.Rules, nil
	case "Role":
		role, err := rbacClient.Roles(rb.Namespace).Get(ctx, rb.RoleRef.Name, v1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("fetching Role %q for RoleBinding %q: %w", rb.RoleRef.Name, rb.Name, err)
		}

		return role.Rules, nil
	}

	return nil, fmt.Errorf("unknown role reference kind: %q", rb.RoleRef.Kind)
}

// RulesForClusterRoleBinding will return a slice of rbacv1.PolicyRule objects
// that are representative of the ClusterRole rules that a ClusterRoleBinding
// references. It returns an error if one occurs during the process of fetching this
// information.
func RulesForClusterRoleBinding(ctx context.Context, crGetter rbacv1client.ClusterRolesGetter, crb *rbacv1.ClusterRoleBinding) ([]rbacv1.PolicyRule, error) {
	role, err := crGetter.ClusterRoles().Get(ctx, crb.RoleRef.Name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("fetching ClusterRole %q for ClusterRoleBinding %q: %w", crb.RoleRef.Name, crb.Name, err)
	}

	return role.Rules, nil
}
