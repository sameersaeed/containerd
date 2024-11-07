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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	dialer "github.com/containerd/containerd/v2/integration/remote/util"
	"github.com/containerd/containerd/v2/internal/cri/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestIssue10244LoopbackV2Host(t *testing.T) {
	for i := 0; i < 2; i++ {
		tBasename := fmt.Sprintf("case-%v", i != 0)

		t.Run(tBasename, func(t *testing.T) {
			assert.True(t, CheckLoopbackResult(t, i != 0))
		})
	}
}

// IsLoInterfaceUp validates whether the lo interface is up
func IsLoInterfaceUp() (bool, error) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return false, fmt.Errorf("Could not find interface lo: %w", err)
	}

	return link.Attrs().Flags&net.FlagUp != 0, nil
}

// CurrentRuntimeClient returns the grpc runtime service client for the current containerd process
func CurrentRuntimeClient(currentProc *ctrdProc) (runtime.RuntimeServiceClient, error) {
	addr, dialer, err := dialer.GetAddressAndDialer(currentProc.grpcAddress())
	if err != nil {
		return nil, fmt.Errorf("Failed to get dialer: %w", err)
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to current CRI endpoint: %w", err)
	}

	return runtime.NewRuntimeServiceClient(conn), nil
}

// SandboxInfoCurrentRuntime gets the sandbox status and info for the current containerd runtime
func SandboxInfoCurrentRuntime(id string, currentProc *ctrdProc) (*runtime.PodSandboxStatus, *types.SandboxInfo, error) {
	client, err := CurrentRuntimeClient(currentProc)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create new client for current runtime")
	}

	resp, err := client.PodSandboxStatus(context.Background(), &runtime.PodSandboxStatusRequest{
		PodSandboxId: id,
		Verbose:      true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get sandbox status")
	}

	var info types.SandboxInfo
	if err := json.Unmarshal([]byte(resp.GetInfo()["info"]), &info); err != nil {
		return nil, nil, fmt.Errorf("Failed to unmarshal sandbox info: %v", err)
	}

	return resp.GetStatus(), &info, nil
}

// CheckLoopbackResult checks whether the status of the loopback interface is UP or DOWN
func CheckLoopbackResult(t *testing.T, useInternalLoopback bool) bool {
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

	t.Logf("Start containerd process")
	currentProc := newCtrdProc(t, "containerd", workDir, nil)
	require.NoError(t, currentProc.isReady())

	t.Cleanup(func() {
		t.Log("Cleanup all the pods")
		cleanupPods(t, currentProc.criRuntimeService(t))

		t.Log("Stop containerd process")
		require.NoError(t, currentProc.kill(syscall.SIGTERM))
		require.NoError(t, currentProc.wait(5*time.Minute))
	})

	t.Log("Create and run a sandbox pod")
	pod, err := currentProc.criRuntimeService(t).RunPodSandbox(PodSandboxConfig("host-exec-lo-test", "sandbox"), "")
	require.NoError(t, err, "Failed to run pod sandbox in host containerd process")

	_, info, err := SandboxInfoCurrentRuntime(pod, currentProc)
	require.NoError(t, err, "Failed to get sandbox info for current containerd runtime")

	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()

	t.Log("Exec'ing into pod network namespace")
	netnsPath := info.Metadata.NetNSPath
	require.NoError(t, err, "Could not find pod network namespace at '/var/run/netns'")
	t.Logf("Found pod network namespace: %s", strings.Split(netnsPath, "/")[4])

	originalNetNS, err := netns.Get()
	require.NoError(t, err, "Failed to get original network namespace")
	t.Logf("Current network namespace: %s", originalNetNS)

	podNetNS, err := netns.GetFromPath(netnsPath)
	require.NoError(t, err, "Could not get pod network namespace")

	err = netns.Set(podNetNS)
	require.NoError(t, err, "Failed to switch to pod network namespace")
	t.Logf("Switched to pod network namespace: %s", podNetNS)

	defer func() {
		err = netns.Set(originalNetNS)
		require.NoError(t, err, "Failed to switch back to original network namespace")
		t.Logf("Returned to the original network namespace: %s", originalNetNS)
	}()

	t.Log("Check loopback status while exec'd into the pod network namespace")
	t.Logf("Loopback interface status should be UP (not DOWN) when 'use_internal_loopback' is '%t'", useInternalLoopback)
	up, err := IsLoInterfaceUp()
	if err != nil {
		log.Fatalf("Could not check lo interface status: %v", err)
	}
	t.Logf("Loopback interface is %s", map[bool]string{true: "UP", false: "DOWN"}[up])

	return up
}
