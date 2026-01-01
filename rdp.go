package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"remotegateway/internal/virt"
)

const (
	defaultRDPAddress = "workstation:3389"
	defaultRDPPort    = "3389"
	rdpFilename       = "rdpgw.rdp"
)

const indexHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RDP Gateway</title>
    <style>
      :root {
        --bg: #0b1224;
        --panel: #0f172a;
        --accent: #38bdf8;
        --muted: #94a3b8;
        --line: rgba(255,255,255,0.1);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Space Grotesk", "Segoe UI", sans-serif;
        background:
          radial-gradient(circle at 15% 15%, rgba(56,189,248,0.18), transparent 40%),
          radial-gradient(circle at 85% 5%, rgba(14,165,233,0.12), transparent 35%),
          var(--bg);
        color: #e2e8f0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
      }
      .card {
        width: min(1100px, 100%);
        background: linear-gradient(160deg, rgba(15,23,42,0.96), rgba(2,6,23,0.96));
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 32px;
        box-shadow: 0 24px 70px rgba(0,0,0,0.4);
      }
      .vm-panel {
        margin-top: 0;
        padding: 18px;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: #0b1224;
      }
      .vm-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .vm-panel h2 {
        margin: 0 0 6px;
        font-size: clamp(20px, 2.6vw, 30px);
        color: var(--accent);
      }
      .logout-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 8px 14px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: transparent;
        color: var(--muted);
        text-decoration: none;
        font-weight: 600;
        font-size: 12px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .logout-button:hover {
        border-color: rgba(56,189,248,0.6);
        color: #e2e8f0;
        background: rgba(56,189,248,0.08);
      }
      .vm-subtitle {
        margin: 4px 0 16px;
        color: var(--muted);
        font-size: 14px;
      }
      .vm-form {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: flex-end;
        margin-bottom: 12px;
      }
      .vm-form .field {
        flex: 1 1 240px;
        min-width: 220px;
      }
      .vm-form label {
        display: block;
        margin-bottom: 6px;
        font-size: 12px;
        color: var(--muted);
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .vm-form input {
        width: 100%;
        box-sizing: border-box;
        background: #0b1224;
        border: 1px solid var(--line);
        color: #e2e8f0;
        border-radius: 10px;
        padding: 10px 12px;
        font-size: 14px;
      }
      .vm-form button {
        border: 0;
        border-radius: 10px;
        padding: 10px 16px;
        font-weight: 600;
        background: var(--accent);
        color: #062238;
        cursor: pointer;
      }
      .vm-form button:disabled,
      .vm-remove:disabled,
      .vm-power:disabled {
        opacity: 0.6;
        cursor: not-allowed;
      }
      .vm-success {
        margin: 12px 0 0;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid rgba(56,189,248,0.4);
        background: rgba(56,189,248,0.12);
        color: #bae6fd;
        font-weight: 600;
        font-size: 13px;
      }
      .vm-table-wrap {
        margin-top: 12px;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: #0f172a;
        overflow-x: auto;
      }
      .vm-table {
        width: 100%;
        border-collapse: collapse;
        min-width: 720px;
        font-size: 14px;
      }
      .vm-table th {
        text-align: left;
        font-size: 12px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        padding: 10px 12px;
        background: #0b1224;
      }
      .vm-table td {
        padding: 10px 12px;
        border-top: 1px solid var(--line);
      }
      .vm-table tbody tr:hover {
        background: rgba(56,189,248,0.08);
      }
      .vm-name {
        font-weight: 600;
      }
      .vm-state {
        color: var(--accent);
        font-weight: 600;
      }
      .vm-download {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 8px 14px;
        border-radius: 10px;
        background: var(--accent);
        color: #062238;
        text-decoration: none;
        font-weight: 600;
        font-size: 12px;
      }
      .vm-download:hover {
        filter: brightness(1.05);
      }
      .vm-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
      }
      .vm-power {
        border: 1px solid rgba(148,163,184,0.5);
        background: transparent;
        color: #e2e8f0;
        border-radius: 10px;
        padding: 8px 12px;
        font-weight: 600;
        font-size: 12px;
        cursor: pointer;
      }
      .vm-power:hover {
        background: rgba(148,163,184,0.12);
      }
      .vm-start {
        border-color: rgba(34,197,94,0.6);
        color: #bbf7d0;
      }
      .vm-start:hover {
        background: rgba(34,197,94,0.12);
      }
      .vm-restart {
        border-color: rgba(250,204,21,0.6);
        color: #fde68a;
      }
      .vm-restart:hover {
        background: rgba(250,204,21,0.12);
      }
      .vm-shutdown {
        border-color: rgba(251,146,60,0.6);
        color: #fed7aa;
      }
      .vm-shutdown:hover {
        background: rgba(251,146,60,0.12);
      }
      .vm-remove {
        border: 1px solid rgba(248,113,113,0.6);
        background: transparent;
        color: #fecaca;
        border-radius: 10px;
        padding: 8px 12px;
        font-weight: 600;
        font-size: 12px;
        cursor: pointer;
      }
      .vm-remove:hover {
        background: rgba(248,113,113,0.12);
      }
      .vm-error {
        margin: 12px 0 0;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid rgba(248,113,113,0.4);
        background: rgba(248,113,113,0.12);
        color: #fecaca;
        font-weight: 600;
        font-size: 13px;
      }
      .vm-empty,
      .vm-loading {
        margin: 12px 0 0;
        color: var(--muted);
      }
      .vm-disabled {
        color: var(--muted);
      }
    </style>
  </head>
  <body>
    <div id="app"></div>
    <noscript>
      <main class="card">
        <section class="vm-panel">
          <div class="vm-header">
            <h2>Available VMs</h2>
          </div>
          <p class="vm-error">JavaScript is required to use the dashboard.</p>
        </section>
      </main>
    </noscript>
    <script defer src="/static/dashboard.js"></script>
  </body>
</html>
`

type dashboardVM struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	RDPHost   string `json:"rdpHost"`
	State     string `json:"state"`
	MemoryMiB int    `json:"memoryMiB"`
	VCPU      int    `json:"vcpu"`
	VolumeGB  int    `json:"volumeGB"`
}

type dashboardDataResponse struct {
	Filename string        `json:"filename"`
	VMs      []dashboardVM `json:"vms"`
	Error    string        `json:"error,omitempty"`
}

type dashboardActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func renderDashboardPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(indexHTML)); err != nil {
		log.Printf("render dashboard page: %v", err)
	}
}

func listDashboardVMs() ([]dashboardVM, error) {
	vmList, err := virt.ListVMs("")
	if err != nil {
		return nil, err
	}
	rows := make([]dashboardVM, 0, len(vmList))
	for _, vm := range vmList {
		rdpHost := rdpTargetHost(vm.Name)
		rows = append(rows, dashboardVM{
			Name:      vm.Name,
			IP:        vm.IP,
			RDPHost:   rdpHost,
			State:     vm.State,
			MemoryMiB: vm.MemoryMiB,
			VCPU:      vm.VCPU,
			VolumeGB:  vm.VolumeGB,
		})
	}
	return rows, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func rdpTargetFromRequest(r *http.Request) string {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		return defaultRDPAddress
	}
	return rdpTargetHost(target)
}

func rdpTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if hasPort(target) {
		return target
	}
	return addPort(target, defaultRDPPort)
}

func gatewayHostFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host != "" {
		if idx := strings.Index(host, ","); idx >= 0 {
			host = strings.TrimSpace(host[:idx])
		}
	} else {
		host = strings.TrimSpace(r.Host)
	}

	if host == "" {
		return "localhost:8443"
	}

	port := strings.TrimSpace(r.Header.Get("X-Forwarded-Port"))
	if port != "" && !hasPort(host) {
		host = addPort(host, port)
	}
	return host
}

func hasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

func addPort(host, port string) string {
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

func rdpFileContent(gatewayHost, targetHost string) string {
	var b strings.Builder
	write := func(line string) {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	write("screen mode id:i:2")
	write("full address:s:" + targetHost)
	write("gatewayhostname:s:" + gatewayHost)
	write("gatewayusagemethod:i:2")
	write("gatewaycredentialssource:i:4")
	write("gatewayprofileusagemethod:i:1")
	write("promptcredentialonce:i:0")
	write("authentication level:i:2")
	write("use redirection server name:i:1")
	return b.String()
}
