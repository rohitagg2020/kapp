// Copyright 2024 The Carvel Authors.
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreflightCRDUpgradeSafetyInvalidFieldChangeMinLengthIncreased(t *testing.T) {
	env := BuildEnv(t)
	logger := Logger{}
	kapp := Kapp{t, env.Namespace, env.KappBinaryPath, logger}

	testName := "preflightcrdupgradesafetyinvalidfieldchangeminlengthincreased"

	base := `
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.13.0
  name: memcacheds.__test-name__.example.com
spec:
  group: __test-name__.example.com
  names:
    kind: Memcached
    listKind: MemcachedList
    plural: memcacheds
    singular: memcached
  scope: Namespaced
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            type: string
          kind:
            type: string
          metadata:
            type: object
          spec:
            minLength: 5
            type: string
          status:
            type: object
        type: object
    served: true
    storage: true
    subresources:
      status: {}
`

	base = strings.ReplaceAll(base, "__test-name__", testName)
	appName := "preflight-crdupgradesafety-app"

	cleanUp := func() {
		kapp.Run([]string{"delete", "-a", appName})
	}
	cleanUp()
	defer cleanUp()

	update := `
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.13.0
  name: memcacheds.__test-name__.example.com
spec:
  group: __test-name__.example.com
  names:
    kind: Memcached
    listKind: MemcachedList
    plural: memcacheds
    singular: memcached
  scope: Namespaced
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            type: string
          kind:
            type: string
          metadata:
            type: object
          spec:
            minLength: 10
            type: string
          status:
            type: object
        type: object
    served: true
    storage: true
    subresources:
      status: {}
`

	update = strings.ReplaceAll(update, "__test-name__", testName)
	logger.Section("deploy app with CRD update that increases minimum length constraint for existing field, preflight check enabled, should error", func() {
		_, err := kapp.RunWithOpts([]string{"deploy", "-a", appName, "-f", "-"}, RunOpts{StdinReader: strings.NewReader(base)})
		require.NoError(t, err)
		_, err = kapp.RunWithOpts([]string{"deploy", "--preflight=CRDUpgradeSafety", "-a", appName, "-f", "-"},
			RunOpts{StdinReader: strings.NewReader(update), AllowError: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), "minimum length constraint increased")
	})
}
