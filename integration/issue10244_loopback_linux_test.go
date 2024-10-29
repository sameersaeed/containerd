/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/integration/images"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	criruntime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestIssue10244LoopbackV2(t *testing.T) {
	checkLoopbackResult(t, true)
	checkLoopbackResult(t, false)
}

func checkLoopbackResult(t *testing.T, useInternalLoopback bool) {
	t.Logf("Create containerd config with 'use_internal_loopback' set to '%t'", useInternalLoopback)
	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "config.toml")
	ctrdConfig := fmt.Sprintf(`
	version = 3

	[plugins]
	[plugins.'io.containerd.cri.v1.runtime']
	  [plugins.'io.containerd.cri.v1.runtime'.cni]
		use_internal_loopback = %t`,
		useInternalLoopback)

	err := os.WriteFile(configPath, []byte(ctrdConfig), 0600)
	require.NoError(t, err)

	t.Logf("Start containerd")
	currentProc := newCtrdProc(t, "containerd", workDir, nil)
	require.NoError(t, currentProc.isReady())

	t.Cleanup(func() {
		t.Log("Cleanup all the pods")
		cleanupPods(t, currentProc.criRuntimeService(t))

		t.Log("Stop containerd process")
		require.NoError(t, currentProc.kill(syscall.SIGTERM))
		require.NoError(t, currentProc.wait(5*time.Minute))
	})

	var (
		testImage     = images.Get(images.BusyBox)
		containerName = "test-container-loopback-v2"
	)

	EnsureImageExists(t, testImage)

	imageName := images.Get(images.BusyBox)
	pullImagesByCRI(t, currentProc.criImageService(t), imageName)

	podCtx := newPodTCtx(t, currentProc.criRuntimeService(t), "container-exec-lo-test", "sandbox")
	cnID := podCtx.createContainer(
		containerName,
		imageName,
		criruntime.ContainerState_CONTAINER_RUNNING,
		WithCommand("sleep", "1d"),
	)

	t.Log("Exec in container")
	stdout, _, err := podCtx.rSvc.ExecSync(cnID, []string{"sh", "-c", "ip address"}, 5*time.Second)
	require.NoError(t, err, "")

	t.Logf("Loopback interface (127.0.0.1/8 scope host lo) should be present when 'use_internal_loopback' is '%t':\n%s\n", useInternalLoopback, string(stdout))
	assert.Contains(t, string(stdout), "127.0.0.1/8 scope host lo")
}
