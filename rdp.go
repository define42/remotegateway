package main

import (
	"html/template"
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
      .vm-empty {
        margin: 12px 0 0;
        color: var(--muted);
      }
    </style>
  </head>
  <body>
    <main class="card">
      <section class="vm-panel">
        <div class="vm-header">
          <h2>Available VMs</h2>
          <a class="logout-button" href="/logout">Logout</a>
        </div>
        <p class="vm-subtitle">Live inventory from libvirt.</p>
        {{if .VMError}}
          <p class="vm-error">{{.VMError}}</p>
        {{else if .VMs}}
          <div class="vm-table-wrap">
            <table class="vm-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>IP Address</th>
                  <th>State</th>
                  <th>Memory</th>
                  <th>vCPU</th>
                  <th>Disk</th>
                  <th>RDP</th>
                </tr>
              </thead>
              <tbody>
                {{range .VMs}}
                <tr>
                  <td class="vm-name">{{.Name}}</td>
                  <td>{{if .IP}}{{.IP}}{{else}}n/a{{end}}</td>
                  <td class="vm-state">{{.State}}</td>
                  <td>{{if .MemoryMiB}}{{.MemoryMiB}} MiB{{else}}n/a{{end}}</td>
                  <td>{{if .VCPU}}{{.VCPU}}{{else}}n/a{{end}}</td>
                  <td>{{if .VolumeGB}}{{.VolumeGB}} GB{{else}}n/a{{end}}</td>
                  <td>
                    {{if .RDPHost}}
                      <a class="vm-download" href="/api/{{$.Filename}}?target={{.RDPHost | urlquery}}">Download</a>
                    {{else}}
                      n/a
                    {{end}}
                  </td>
                </tr>
                {{end}}
              </tbody>
            </table>
          </div>
        {{else}}
          <p class="vm-empty">No virtual machines found.</p>
        {{end}}
      </section>
    </main>
  </body>
</html>
`

var dashboardTemplate = template.Must(template.New("dashboard").Parse(indexHTML))

type indexVM struct {
	Name      string
	IP        string
	RDPHost   string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
}

func renderDashboardPage(w http.ResponseWriter, gatewayHost, targetHost string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	vmList, err := virt.ListVMs("")
	var vmRows []indexVM
	var vmError string
	if err != nil {
		log.Printf("list vms: %v", err)
		vmError = "Unable to load virtual machines right now."
	} else {
		vmRows = make([]indexVM, 0, len(vmList))
		for _, vm := range vmList {
			/*
				targetHost := vm.PrimaryIP
				if targetHost == "" {
					targetHost = vm.Name
				}*/
			rdpHost := rdpTargetHost(vm.Name)
			vmRows = append(vmRows, indexVM{
				Name:      vm.Name,
				IP:        vm.IP,
				RDPHost:   rdpHost,
				State:     vm.State,
				MemoryMiB: vm.MemoryMiB,
				VCPU:      vm.VCPU,
				VolumeGB:  vm.VolumeGB,
			})
		}
	}
	data := struct {
		Gateway  string
		Target   string
		Filename string
		VMs      []indexVM
		VMError  string
	}{
		Gateway:  gatewayHost,
		Target:   targetHost,
		Filename: rdpFilename,
		VMs:      vmRows,
		VMError:  vmError,
	}
	if err := dashboardTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
		return
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
