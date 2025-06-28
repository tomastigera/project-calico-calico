package main

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/projectcalico/calico/test-tools/fake-guardian/pkg/linseed"
	"github.com/projectcalico/calico/test-tools/fake-guardian/pkg/voltron/client"
	"github.com/projectcalico/calico/test-tools/fake-guardian/pkg/voltron/proxy"
)

const (
	fipsModeEnabled = false
)

// ClusterConfig describes the cluster configuration for running fake-guardian
type ClusterConfig struct {
	name                   string
	voltronURL             string
	proxyListenerPort      int
	clientKeyPem           []byte
	clientCertPem          []byte
	caCert                 *x509.CertPool
	realTigeraCABundlePath string
	realSATokenPath        string
	realAPIServerCAPath    string
	realAPIServerURL       string
	envtestBinDir          string
}

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
	slog.String("category", "main"),
)

type config struct {
	StatefulSet            bool   `default:"false" split_words:"true"`
	ClusterID              int    `default:"0" split_words:"true"`
	ProxyListenPort        int    `default:"0" split_words:"true"`
	MetricsPort            int    `default:"2112" split_words:"true"`
	RealTigeraCABundlePath string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`
	RealSATokenPath        string `default:"/var/run/secrets/kubernetes.io/serviceaccount/token" split_words:"true"`
	RealAPIServerCAPath    string `default:"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" split_words:"true"`
	RealAPIServerURL       string `default:"https://kubernetes.default" split_words:"true"`
	EnvtestBinDir          string `default:"/usr/share/kubebuilder-envtest" split_words:"true"`
	ProxyLogLevel          string `default:"INFO" split_words:"true"`

	FlowPublishBatchSize    int           `default:"0" split_words:"true"`
	FlowPublishInterval     time.Duration `default:"15s" split_words:"true"`
	FlowPublishInitialDelay time.Duration `default:"15s" split_words:"true"`
}

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {

	cfg := config{}
	if err := envconfig.Process("FAKE_GUARDIAN", &cfg); err != nil {
		return err
	}

	logger.Info("starting", slog.String("config", fmt.Sprintf("%+v", cfg)))

	k8sClient, err := newK8sClient()
	if err != nil {
		return err
	}

	namespace := os.Getenv("MY_POD_NAMESPACE")

	if cfg.StatefulSet {
		// get the instanceNumber from the pod hostname
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname")
		}

		hostnameParts := strings.Split(hostname, "-")
		podNumber, err := strconv.Atoi(hostnameParts[len(hostnameParts)-1])
		if err != nil {
			return fmt.Errorf("failed to get cluster number from hostname %v", hostnameParts)
		}

		cfg.ClusterID = podNumber
	}

	secret, err := getClusterSecret(k8sClient, namespace, cfg.ClusterID)
	if err != nil {
		return err
	}

	return runFakeCluster(*secret, cfg)
}

func getClusterSecret(client kubernetes.Interface, namespace string, clusterID int) (*v1.Secret, error) {
	clusterName := fmt.Sprintf("fake-cluster-%03d", clusterID)

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), clusterName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster secret %v: %w", clusterName, err)
	}
	return secret, nil
}

func startMetricsServer(ctx context.Context, errChan chan error, port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		logger.Info("starting metrics server", slog.String("port", fmt.Sprintf("%d", port)))
		if err := server.ListenAndServe(); err != nil {
			logger.Error("failed to start metrics server", slog.String("err", err.Error()))
			errChan <- fmt.Errorf("failed to start metrics server: %w", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Info("failed to shutdown metrics server", slog.String("err", err.Error()))
	}

	logger.Info("metrics server stopped")
}

type impersonationRemovalRoundTripper struct {
	next http.RoundTripper
}

func (rt impersonationRemovalRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Del("Impersonate-User")
	r.Header.Del("Impersonate-Group")
	return rt.next.RoundTrip(r)
}

func runFakeCluster(secret v1.Secret, cfg config) error {
	logger := logger.With(slog.String("clusterName", secret.Name))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	proxyLogLevel, err := parseLogLevel(cfg.ProxyLogLevel)
	if err != nil {
		return err
	}

	if cfg.MetricsPort > 0 {
		go startMetricsServer(ctx, errChan, cfg.MetricsPort)
	}

	caCerts, err := loadCertificatesFromPEM(secret.Data["management-cluster.crt"])
	if err != nil {
		return fmt.Errorf("failed to load management-cluster.crt: %w", err)
	}
	caCertPool := x509.NewCertPool()
	for _, caCert := range caCerts {
		caCertPool.AddCert(caCert)
	}

	serverName, err := dnsNameFromCert(caCerts[0])
	if err != nil {
		return fmt.Errorf("failed to get server name from ca cert: %w", err)
	}

	dataGenerator, err := linseed.NewDataGenerator()
	if err != nil {
		return fmt.Errorf("failed to create data generator: %w", err)
	}

	clusterCfg := ClusterConfig{
		name:                   secret.Name,
		voltronURL:             string(secret.Data["voltron-url"]),
		proxyListenerPort:      cfg.ProxyListenPort,
		clientKeyPem:           secret.Data["managed-cluster.key"],
		clientCertPem:          secret.Data["managed-cluster.crt"],
		caCert:                 caCertPool,
		realTigeraCABundlePath: cfg.RealTigeraCABundlePath,
		realAPIServerURL:       cfg.RealAPIServerURL,
		realAPIServerCAPath:    cfg.RealAPIServerCAPath,
		realSATokenPath:        cfg.RealSATokenPath,
		envtestBinDir:          cfg.EnvtestBinDir,
	}

	testEnvCfg := &envtest.Environment{
		BinaryAssetsDirectory:    cfg.EnvtestBinDir,
		CRDDirectoryPaths:        []string{},
		ErrorIfCRDPathMissing:    true,
		AttachControlPlaneOutput: true,
	}

	testEnvCfg.ControlPlane.GetAPIServer().Configure()
	testEnv, err := testEnvCfg.Start()
	if err != nil {
		return err
	}

	testEnvClient, err := kubernetes.NewForConfig(testEnv)
	if err != nil {
		return err
	}

	err = createNamespaces(ctx, testEnvClient,
		"tigera-operator",
		"tigera-image-assurance",
		"tigera-compliance",
		"tigera-intrusion-detection",
		"tigera-fluentd",
		"tigera-dpi",
	)
	if err != nil {
		return err
	}

	testEnvTransport, err := rest.TransportFor(testEnv)
	if err != nil {
		return err
	}
	testEnvTransport = &impersonationRemovalRoundTripper{
		next: testEnvTransport,
	}

	realSATokenBytes, err := os.ReadFile(clusterCfg.realSATokenPath)
	if err != nil {
		return err
	}

	mustParseURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		return u
	}

	realSAToken := strings.TrimSpace(string(realSATokenBytes))
	targets := []proxy.Target{

		{
			Path:     "/apis/projectcalico.org/",
			Dest:     mustParseURL(clusterCfg.realAPIServerURL),
			CAPem:    clusterCfg.realAPIServerCAPath,
			Token:    realSAToken,
			LogLevel: proxyLogLevel,
		},
		{
			Path:     "/apis/operator.tigera.io/",
			Dest:     mustParseURL(clusterCfg.realAPIServerURL),
			CAPem:    clusterCfg.realAPIServerCAPath,
			Token:    realSAToken,
			LogLevel: proxyLogLevel,
		},
		{
			Path:             "/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/",
			Dest:             mustParseURL("https://prometheus-http-api.tigera-prometheus.svc:9090"),
			PathRegexp:       regexp.MustCompile(fmt.Sprintf("^%v/?", "/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/")),
			PathReplace:      []byte("/"),
			CAPem:            clusterCfg.realTigeraCABundlePath,
			AllowInsecureTLS: true,
			Token:            realSAToken,
			LogLevel:         proxyLogLevel,
		},
		{
			Path:             "/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy/",
			Dest:             mustParseURL("https://calico-api.calico-system.svc:8080"),
			PathRegexp:       regexp.MustCompile(fmt.Sprintf("^%v/?", "/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy/")),
			PathReplace:      []byte("/"),
			CAPem:            clusterCfg.realTigeraCABundlePath,
			AllowInsecureTLS: true,
			Token:            realSAToken,
			LogLevel:         slog.LevelInfo,
		},
		{
			Path:      "/api/",
			Dest:      mustParseURL(testEnv.Host),
			Transport: testEnvTransport,
			LogLevel:  proxyLogLevel,
		},
		{
			Path:      "/apis/",
			Dest:      mustParseURL(testEnv.Host),
			Transport: testEnvTransport,
			LogLevel:  proxyLogLevel,
		},
		{
			Path:             "/packet-capture/",
			Dest:             mustParseURL("https://tigera-packetcapture.tigera-packetcapture.svc"),
			AllowInsecureTLS: true,
			PathRegexp:       regexp.MustCompile("^/packet-capture/?"),
			PathReplace:      []byte("/"),
			CAPem:            clusterCfg.realTigeraCABundlePath,
			Token:            realSAToken,
			LogLevel:         proxyLogLevel,
		},
	}

	go func() {
		for i := 1; i <= 10; i++ {
			runGuardian(ctx, errChan, clusterCfg, serverName, targets, logger)

			logger.Info("runGuardian exited, retrying in 5 seconds")
			time.Sleep(5 * time.Second)
		}

		logger.Info("tunnel retries exhausted, shutting down")
	}()

	if clusterCfg.proxyListenerPort > 0 && cfg.FlowPublishBatchSize > 0 {
		linseedClient, err := linseed.NewClient(testEnvClient, secret.Namespace, clusterCfg.proxyListenerPort)
		if err != nil {
			return err
		}

		go func() {
			logger.Info("starting flow generator after initial delay", slog.String("initialDelay", cfg.FlowPublishInitialDelay.String()))
			time.Sleep(cfg.FlowPublishInitialDelay)
			startFlowPublisher(ctx, cfg.FlowPublishInterval, cfg.FlowPublishBatchSize, dataGenerator, linseedClient, logger)
		}()
	}

	select {
	case <-signalChan:
		logger.Info("interrupt signal received. Shutting down...")
	case err := <-errChan:
		logger.Info("error channel notified, shutting down", slog.String("err", err.Error()))
	}

	logger.Info("exiting")

	return nil
}

func startFlowPublisher(ctx context.Context, tickInterval time.Duration, batchSize int, dataGenerator *linseed.DataGenerator, linseedClient *linseed.Client, logger *slog.Logger) {
	ticker := time.NewTicker(tickInterval)

	for {
		select {

		case <-ctx.Done():
			logger.Info("flow generator exiting")
			return

		case <-ticker.C:
			logger.Info("posting flow logs", slog.Int("batchSize", batchSize))
			flows := dataGenerator.GenerateFlows(batchSize)
			resp, err := linseedClient.PostFlowLogs(context.Background(), flows)
			if err != nil {
				logger.Error("failed to post flow logs", slog.String("err", err.Error()))
			} else {
				logger.Info("posted flow logs", slog.String("response", fmt.Sprintf("%+v", resp)))
			}
		}
	}
}

func runGuardian(ctx context.Context, errChan chan error, clusterCfg ClusterConfig, serverName string, targets []proxy.Target, logger *slog.Logger) {

	cli, err := client.New(
		clusterCfg.voltronURL,
		serverName,
		client.WithKeepAliveSettings(true, 1000),
		client.WithProxyTargets(targets),
		client.WithTunnelCreds(clusterCfg.clientCertPem, clusterCfg.clientKeyPem),
		client.WithTunnelRootCA(clusterCfg.caCert),
		client.WithTunnelDialRetryAttempts(20),
		client.WithTunnelDialRetryInterval(5*time.Second),
		client.WithTunnelDialTimeout(6*time.Second),
		client.WithConnectionRetryAttempts(20),
		client.WithConnectionRetryInterval(5*time.Second),
		client.WithFIPSModeEnabled(fipsModeEnabled),
	)
	if err != nil {
		logger.Error("Failed to create client", slog.String("err", err.Error()))
	}

	go func() {
		if err := cli.ServeTunnelHTTP(); err != nil {
			logger.Error("serving the tunnel exited", slog.String("err", err.Error()))
			errChan <- fmt.Errorf("serving the tunnel exited: %w", err)
		}
	}()

	if proxyPort := clusterCfg.proxyListenerPort; proxyPort > 0 {
		logger.Info("listening for connections to proxy to voltron",
			slog.Int("port", proxyPort),
		)

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", proxyPort))
		if err != nil {
			logger.Error("failed to listen", slog.String("err", err.Error()))
		}

		go func() {
			if err := cli.AcceptAndProxy(listener); err != nil {
				errChan <- fmt.Errorf("proxy tunnel exited: %w", err)
				logger.Error("proxy tunnel exited with an error", slog.String("err", err.Error()))
			}
		}()
	}

	<-ctx.Done()

	if err := cli.Close(); err != nil {
		logger.Error("failed to close client", slog.String("err", err.Error()))
	}
}

func createNamespaces(ctx context.Context, client kubernetes.Interface, names ...string) error {
	namespaces := client.CoreV1().Namespaces()

	for _, name := range names {
		_, err := namespaces.Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func newK8sClient() (kubernetes.Interface, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			return nil, err
		}
		// failed in cluster config. checking for kubeconfig
		restConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(restConfig)
}

func dnsNameFromCert(cert *x509.Certificate) (string, error) {
	if len(cert.DNSNames) == 0 {
		return "", fmt.Errorf("no DNS names in certificate")
	}
	return cert.DNSNames[0], nil
}

func loadCertificatesFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	var remainder = pemData

	for {
		block, remainder = pem.Decode(remainder)
		if block == nil {
			break // No more PEM blocks
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q", level)
	}
}
