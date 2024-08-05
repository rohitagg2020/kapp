// Copyright 2024 The Carvel Authors.
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectiveOwnershipOverride(t *testing.T) {
	env := BuildEnv(t)
	logger := Logger{}
	kapp := Kapp{t, env.Namespace, env.KappBinaryPath, logger}

	const existingAppName1 = "existing-app-1"
	const existingAppName2 = "existing-app-2"
	const newAppName = "new-app"

	resourceYAML := `
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-%s
data:
  foo: bar
`

	cleanUp := func() {
		kapp.Run([]string{"delete", "-a", existingAppName1})
		kapp.Run([]string{"delete", "-a", existingAppName2})
		kapp.Run([]string{"delete", "-a", newAppName})
	}
	cleanUp()
	defer cleanUp()

	logger.Section("deploy existing apps", func() {
		kapp.RunWithOpts([]string{"deploy", "-a", existingAppName1, "-f", "-"}, RunOpts{StdinReader: strings.NewReader(fmt.Sprintf(resourceYAML, "1"))})
		kapp.RunWithOpts([]string{"deploy", "-a", existingAppName2, "-f", "-"}, RunOpts{StdinReader: strings.NewReader(fmt.Sprintf(resourceYAML, "2"))})
	})

	logger.Section("deploy new app with selective overrides", func() {
		resourcesString := fmt.Sprintf("%s%s", fmt.Sprintf(resourceYAML, "1"), fmt.Sprintf(resourceYAML, "2"))
		// Overrides disallowed
		_, err := kapp.RunWithOpts([]string{"deploy", "-a", newAppName, "-f", "-"}, RunOpts{StdinReader: strings.NewReader(resourcesString), AllowError: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), existingAppName1)
		require.Contains(t, err.Error(), existingAppName2)

		// Test with override scoped while override is disallowed
		_, err = kapp.RunWithOpts([]string{"deploy", "-a", newAppName, "-f", "-", "--ownership-override-allowed-apps", existingAppName1},
			RunOpts{StdinReader: strings.NewReader(resourcesString), AllowError: true})
		require.Error(t, err)
		require.Contains(t, err.Error(), existingAppName1)
		require.Contains(t, err.Error(), existingAppName2)

		// Test with override scoped to single existing app
		_, err = kapp.RunWithOpts([]string{"deploy", "-a", newAppName, "-f", "-", "--dangerous-override-ownership-of-existing-resources", "--ownership-override-allowed-apps", existingAppName1},
			RunOpts{StdinReader: strings.NewReader(resourcesString), AllowError: true})
		require.Error(t, err)
		require.NotContains(t, err.Error(), existingAppName1)
		require.Contains(t, err.Error(), existingAppName2)

		// Test with override scoped to both existing app
		kapp.RunWithOpts([]string{"deploy", "-a", newAppName, "-f", "-", "--dangerous-override-ownership-of-existing-resources", "--ownership-override-allowed-apps", fmt.Sprintf("%s,%s", existingAppName1, existingAppName2)},
			RunOpts{StdinReader: strings.NewReader(resourcesString)})
	})
}
