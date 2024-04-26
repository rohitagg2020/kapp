// Copyright 2024 The Carvel Authors.
// SPDX-License-Identifier: Apache-2.0

package crdupgradesafety

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/openshift/crd-schema-checker/pkg/manifestcomparators"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ChangeValidation is a function that accepts a FieldDiff
// as a parameter and should return:
// - a boolean representation of whether or not the change
// - an error if the change would be unsafe
// has been fully handled (i.e no additional changes exist)
type ChangeValidation func(diff FieldDiff) (bool, error)

// EnumChangeValidation ensures that:
// - No enums are added to a field that did not previously have
// enum restrictions
// - No enums are removed from a field
// This function returns:
// - A boolean representation of whether or not the change
// has been fully handled (i.e the only change was to enum values)
// - An error if either of the above validations are not satisfied
func EnumChangeValidation(diff FieldDiff) (bool, error) {
	// This function resets the enum values for the
	// old and new field and compares them to determine
	// if there are any additional changes that should be
	// handled. Reseting the enum values allows for chained
	// evaluations to check if they have handled all the changes
	// without having to account for fields other than the ones
	// they are designed to handle. This function should only be called when
	// returning from this function to prevent unnecessary overwrites of
	// these fields.
	handled := func() bool {
		diff.Old.Enum = []v1.JSON{}
		diff.New.Enum = []v1.JSON{}
		return reflect.DeepEqual(diff.Old, diff.New)
	}

	if len(diff.Old.Enum) == 0 && len(diff.New.Enum) > 0 {
		return handled(), fmt.Errorf("enums added when there were no enum restrictions previously")
	}

	oldSet := sets.NewString()
	for _, enum := range diff.Old.Enum {
		if !oldSet.Has(string(enum.Raw)) {
			oldSet.Insert(string(enum.Raw))
		}
	}

	newSet := sets.NewString()
	for _, enum := range diff.New.Enum {
		if !newSet.Has(string(enum.Raw)) {
			newSet.Insert(string(enum.Raw))
		}
	}

	diffSet := oldSet.Difference(newSet)
	if diffSet.Len() > 0 {
		return handled(), fmt.Errorf("enum values removed: %+v", diffSet.UnsortedList())
	}

	return handled(), nil
}

// RequiredFieldChangeValidation adds a validation check to ensure that
// existing required fields can be marked as optional in a CRD schema:
// - No new values can be added as required that did not previously have
// any required fields present
// - Existing values can be removed from the required field
// This function returns:
// - A boolean representation of whether or not the change
// has been fully handled (i.e. the only change was to required field values)
// - An error if either of the above criteria are not met
func RequiredFieldChangeValidation(diff FieldDiff) (bool, error) {
	handled := func() bool {
		diff.Old.Required = []string{}
		diff.New.Required = []string{}
		return reflect.DeepEqual(diff.Old, diff.New)
	}

	if len(diff.Old.Required) == 0 && len(diff.New.Required) > 0 {
		return handled(), fmt.Errorf("new values added as required when previously no required fields existed: %+v", diff.New.Required)
	}

	oldSet := sets.NewString()
	for _, requiredField := range diff.Old.Required {
		if !oldSet.Has(requiredField) {
			oldSet.Insert(requiredField)
		}
	}

	newSet := sets.NewString()
	for _, requiredField := range diff.New.Required {
		if !newSet.Has(requiredField) {
			newSet.Insert(requiredField)
		}
	}

	diffSet := newSet.Difference(oldSet)
	if diffSet.Len() > 0 {
		return handled(), fmt.Errorf("new required fields added: %+v", diffSet.UnsortedList())
	}

	return handled(), nil
}

// ChangeValidator is a Validation implementation focused on
// handling updates to existing fields in a CRD
type ChangeValidator struct {
	// Validations is a slice of ChangeValidations
	// to run against each changed field
	Validations []ChangeValidation
}

func (cv *ChangeValidator) Name() string {
	return "ChangeValidator"
}

// Validate will compare each version in the provided existing and new CRDs.
// Since the ChangeValidator is tailored to handling updates to existing fields in
// each version of a CRD. As such the following is assumed:
// - Validating the removal of versions during an update is handled outside of this
// validator. If a version in the existing version of the CRD does not exist in the new
// version that version of the CRD is skipped in this validator.
// - Removal of existing fields is unsafe. Regardless of whether or not this is handled
// by a validator outside this one, if a field is present in a version provided by the existing CRD
// but not present in the same version provided by the new CRD this validation will fail.
//
// Additionally, any changes that are not validated and handled by the known ChangeValidations
// are deemed as unsafe and returns an error.
func (cv *ChangeValidator) Validate(old, new v1.CustomResourceDefinition) error {
	errs := []error{}
	for _, version := range old.Spec.Versions {
		newVersion := manifestcomparators.GetVersionByName(&new, version.Name)
		if newVersion == nil {
			// if the new version doesn't exist skip this version
			continue
		}
		flatOld := FlattenSchema(version.Schema.OpenAPIV3Schema)
		flatNew := FlattenSchema(newVersion.Schema.OpenAPIV3Schema)

		diffs, err := CalculateFlatSchemaDiff(flatOld, flatNew)
		if err != nil {
			errs = append(errs, fmt.Errorf("calculating schema diff for CRD version %q", version.Name))
			continue
		}

		for field, diff := range diffs {
			handled := false
			for _, validation := range cv.Validations {
				ok, err := validation(diff)
				if err != nil {
					errs = append(errs, fmt.Errorf("version %q, field %q: %w", version.Name, field, err))
				}
				if ok {
					handled = true
					break
				}
			}

			if !handled {
				errs = append(errs, fmt.Errorf("version %q, field %q has unknown change, refusing to determine that change is safe", version.Name, field))
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type FieldDiff struct {
	Old *v1.JSONSchemaProps
	New *v1.JSONSchemaProps
}

// FlatSchema is a flat representation of a CRD schema.
type FlatSchema map[string]*v1.JSONSchemaProps

// FlattenSchema takes in a CRD version OpenAPIV3Schema and returns
// a flattened representation of it. For example, a CRD with a schema of:
// ```yaml
//
//	...
//	spec:
//	  type: object
//	  properties:
//	    foo:
//	      type: string
//	    bar:
//	      type: string
//	...
//
// ```
// would be represented as:
//
//	map[string]*v1.JSONSchemaProps{
//	   "^": {},
//	   "^.spec": {},
//	   "^.spec.foo": {},
//	   "^.spec.bar": {},
//	}
//
// where "^" represents the "root" schema
func FlattenSchema(schema *v1.JSONSchemaProps) FlatSchema {
	fieldMap := map[string]*v1.JSONSchemaProps{}

	manifestcomparators.SchemaHas(schema,
		field.NewPath("^"),
		field.NewPath("^"),
		nil,
		func(s *v1.JSONSchemaProps, _, simpleLocation *field.Path, _ []*v1.JSONSchemaProps) bool {
			fieldMap[simpleLocation.String()] = s.DeepCopy()
			return false
		})

	return fieldMap
}

// CalculateFlatSchemaDiff finds fields in a FlatSchema that are different
// and returns a mapping of field --> old and new field schemas. If a field
// exists in the old FlatSchema but not the new an empty diff mapping and an error is returned.
func CalculateFlatSchemaDiff(o, n FlatSchema) (map[string]FieldDiff, error) {
	diffMap := map[string]FieldDiff{}
	for field, schema := range o {
		if _, ok := n[field]; !ok {
			return diffMap, fmt.Errorf("field %q in existing not found in new", field)
		}
		newSchema := n[field]

		// Copy the schemas and remove any child properties for comparison.
		// In theory this will focus in on detecting changes for only the
		// field we are looking at and ignore changes in the children fields.
		// Since we are iterating through the map that should have all fields
		// we should still detect changes in the children fields.
		oldCopy := schema.DeepCopy()
		newCopy := newSchema.DeepCopy()
		oldCopy.Properties = nil
		newCopy.Properties = nil
		if !reflect.DeepEqual(oldCopy, newCopy) {
			diffMap[field] = FieldDiff{
				Old: oldCopy,
				New: newCopy,
			}
		}
	}
	return diffMap, nil
}
