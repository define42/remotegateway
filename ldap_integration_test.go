package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticateWithGlauthConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")
	ldapCfg = loadLDAPConfig()

	u, err := ldapAuthenticate("hackers", "dogood")
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

func TestLDAPAuthenticateJohndoeSingleNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")
	prevCfg := ldapCfg
	ldapCfg = loadLDAPConfig()
	t.Cleanup(func() {
		ldapCfg = prevCfg
	})

	u, err := ldapAuthenticateAccess("johndoe", "dogood")
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

func TestCvRouterProxyWithLDAP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	baseURL := setupLDAPProxyServer(t, ctx)

	client := &http.Client{Timeout: 10 * time.Second}
	accessCases := []requestCase{
		{name: "health", method: http.MethodGet, path: "/api/health", wantStatus: http.StatusOK, wantBodyContains: []string{"ok"}},
		{name: "login page", method: http.MethodGet, path: "/login", wantStatus: http.StatusOK, wantBodyContains: []string{"ContainerVault"}},
	}
	assertRequestCases(t, ctx, baseURL, client, accessCases)

	redirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	status, _, header := doRequest(t, ctx, baseURL, redirectClient, http.MethodGet, "/api/dashboard", "", "", nil, nil)
	if status != http.StatusSeeOther {
		t.Fatalf("expected 303 for dashboard redirect, got %d", status)
	}
	if loc := header.Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}

	loginClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	assertLoginSuccess(t, ctx, baseURL, loginClient, "hackers", "dogood")
	assertLoginSuccess(t, ctx, baseURL, loginClient, "serviceuser", "mysecret")
	assertLoginFailure(t, ctx, baseURL, loginClient, "hackers", "wrongpass", "Invalid credentials.")
	assertLoginFailure(t, ctx, baseURL, loginClient, "hackers", "", "Missing credentials.")
}

type requestCase struct {
	name             string
	method           string
	path             string
	user             string
	pass             string
	wantStatus       int
	wantBodyContains []string
}

func doRequest(t *testing.T, ctx context.Context, baseURL string, client *http.Client, method, path, user, pass string, body io.Reader, headers map[string]string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header.Clone()
}

func assertRequestCases(t *testing.T, ctx context.Context, baseURL string, client *http.Client, cases []requestCase) {
	t.Helper()
	for _, tc := range cases {
		status, body, _ := doRequest(t, ctx, baseURL, client, tc.method, tc.path, tc.user, tc.pass, nil, nil)
		if status != tc.wantStatus {
			t.Fatalf("expected %d for %s, got %d: %s", tc.wantStatus, tc.name, status, body)
		}
		for _, want := range tc.wantBodyContains {
			if !strings.Contains(body, want) {
				t.Fatalf("expected body for %s to contain %q, got %q", tc.name, want, body)
			}
		}
	}
}

func assertLoginSuccess(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	status, _, header := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
	if status != http.StatusSeeOther {
		t.Fatalf("expected 303 for login, got %d", status)
	}
	if loc := header.Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
	}
	if !strings.Contains(header.Get("Set-Cookie"), "cv_session=") {
		t.Fatalf("expected session cookie on login")
	}
}

func assertLoginFailure(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password, message string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	status, body, _ := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for login page, got %d: %s", status, body)
	}
	if !strings.Contains(body, message) {
		t.Fatalf("expected login message %q, got %q", message, body)
	}
}

func setupLDAPProxyServer(t *testing.T, ctx context.Context) string {
	t.Helper()

	ldapURL, stopLDAP := startGlauth(ctx, t, "")
	t.Cleanup(stopLDAP)

	registryHost, stopRegistry := startRegistry(ctx, t, "")
	t.Cleanup(stopRegistry)

	configureLDAPEnv(t, ldapURL)

	prevCfg := ldapCfg
	ldapCfg = loadLDAPConfig()
	t.Cleanup(func() {
		ldapCfg = prevCfg
	})

	prevUpstream := upstream
	upstream = mustParse("http://" + registryHost)
	t.Cleanup(func() {
		upstream = prevUpstream
	})

	server := httptest.NewServer(getRemoteGatewayRotuer())
	t.Cleanup(server.Close)

	return server.URL
}

func configureLDAPEnv(t *testing.T, ldapURL string) {
	t.Helper()
	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")
}

func startGlauth(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "testldap", "default-config.cfg")
	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"ldap"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("ldaps://%s:%s", host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func startRegistry(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForListeningPort("5000/tcp").WithStartupTimeout(1 * time.Minute),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"registry"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start registry: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("registry host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5000/tcp")
	if err != nil {
		t.Fatalf("registry port: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.Port()), func() {
		_ = container.Terminate(context.Background())
	}
}

func startProxy(ctx context.Context, t *testing.T, network, certDir string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    ".",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"8443/tcp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: certDir, ContainerFilePath: "/certs", FileMode: 0o755},
		},
		WaitingFor: wait.ForLog("listening on :8443").
			WithStartupTimeout(2 * time.Minute).
			WithPollInterval(2 * time.Second),
	}

	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"proxy"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("proxy host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8443/tcp")
	if err != nil {
		t.Fatalf("proxy port: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.Port()), func() {
		_ = container.Terminate(context.Background())
	}
}

func addDockerTrust(t *testing.T, configDir, registry, certPath string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "certs.d", registry), 0o755); err != nil {
		t.Fatalf("mk cert dir: %v", err)
	}
	dest := filepath.Join(configDir, "certs.d", registry, "ca.crt")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
}

func writeDockerAuth(t *testing.T, configDir, registry, user, pass string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, pass)))
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mk config dir: %v", err)
	}
	cfg := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"},"https://%s":{"auth":"%s"}}}`, registry, auth, registry, auth)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func ensureBaseImage(t *testing.T, configDir, image string) string {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "pull", image)
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker pull %s: %v", image, err)
	}
	return image
}

func dockerTag(t *testing.T, configDir, src, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "tag", src, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker tag: %v\n%s", err, string(out))
	}
}

func dockerPush(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "push", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker push: %v\n%s", err, string(out))
	}
}

func dockerRmi(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "rmi", "-f", target)
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker rmi %s: %v", target, err)
	}
}

func dockerPull(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "pull", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker pull: %v\n%s", err, string(out))
	}
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

func tempDirInRepo(t *testing.T, prefix string) string {
	t.Helper()
	base := pathRelative(t, "..", "tmp")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mk temp base: %v", err)
	}
	dir, err := os.MkdirTemp(base, prefix)
	if err != nil {
		t.Fatalf("mk temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
