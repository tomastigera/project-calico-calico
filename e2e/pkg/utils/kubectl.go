package utils

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/onsi/gomega"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// Kubectl is a wrapper around kubectl commands used in tests. Note that this helper is
// NOT meant to be used for general resource CRUD operations, for that use the client in
// pkg/utils/client.
type Kubectl struct{}

func (k *Kubectl) Logs(ns, label, user string) (string, error) {
	options := []string{"logs"}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}
	if label != "" {
		options = append(options, fmt.Sprintf("-l %s", label))
	}

	output, err := kubectl.NewKubectlCommand(ns, options...).Exec()
	return output, err
}

func (k *Kubectl) Wait(kind, ns, name, user, condition string, timeout time.Duration) error {
	options := []string{"wait", kind, name, "--for", condition, "--timeout", timeout.String()}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}
	_, err := kubectl.NewKubectlCommand(ns, options...).Exec()
	return err
}

// PortForward starts a kubectl port-forward in the background, allocating a random
// local port to avoid conflicts when tests run in parallel. It returns the local port.
func (k *Kubectl) PortForward(ns, pod, remotePort, user string, timeOut chan time.Time) (int, error) {
	localPort, err := getFreePort()
	if err != nil {
		return 0, fmt.Errorf("failed to allocate local port: %w", err)
	}

	k.portForward(ns, pod, fmt.Sprintf("%d:%s", localPort, remotePort), user, timeOut)
	return localPort, nil
}

// PortForwardWithPorts starts a kubectl port-forward with explicit local and remote ports.
func (k *Kubectl) PortForwardWithPorts(ns, pod, localPort, remotePort, user string, timeOut chan time.Time) {
	k.portForward(ns, pod, fmt.Sprintf("%s:%s", localPort, remotePort), user, timeOut)
}

func (k *Kubectl) portForward(ns, pod, portMapping, user string, timeOut chan time.Time) {
	options := []string{"port-forward", pod, portMapping}
	if user != "" {
		options = append(options, fmt.Sprintf("--as=%v", user))
	}

	go func() {
		if _, err := kubectl.NewKubectlCommand(ns, options...).WithTimeout(timeOut).Exec(); err != nil {
			fmt.Fprintf(os.Stderr, "kubectl port-forward %s/%s %s failed: %v\n", ns, pod, portMapping, err)
		}
	}()
}

// WaitForPortForward waits for the port-forward to be ready by making an HTTP GET request to the given URL.
// It waits at most 5 seconds and polls every 100 milliseconds.
func (k *Kubectl) WaitForPortForward(httpClient *http.Client, url string) {
	gomega.Eventually(func() error {
		resp, err := httpClient.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()

		_, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		return nil
	}, 5*time.Second, 100*time.Millisecond).Should(gomega.Succeed(), "timed out waiting for port-forward to %s to be ready", url)
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}
