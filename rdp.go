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
        --bg: #f4efe6;
        --panel: #fff8ee;
        --ink: #1f1a14;
        --muted: #6f6256;
        --accent: #0e6f6a;
        --accent-2: #d47f2a;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Atkinson Hyperlegible", "Segoe UI", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(1000px 400px at 10% -10%, #fbd9b5 0%, transparent 60%),
          radial-gradient(800px 500px at 90% 10%, #c7efe9 0%, transparent 55%),
          linear-gradient(180deg, var(--bg), #fbf8f2 60%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 32px;
      }
      main {
        width: min(880px, 100%);
        background: var(--panel);
        border: 1px solid #efe1d1;
        border-radius: 24px;
        padding: 36px;
        box-shadow: 0 30px 80px rgba(54, 37, 20, 0.12);
        position: relative;
        overflow: hidden;
        animation: lift 500ms ease-out;
      }
      main::after {
        content: "";
        position: absolute;
        inset: 0;
        background: linear-gradient(120deg, rgba(14, 111, 106, 0.08), transparent 40%);
        pointer-events: none;
      }
      @keyframes lift {
        from { transform: translateY(12px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(14, 111, 106, 0.12);
        color: var(--accent);
        padding: 6px 12px;
        border-radius: 999px;
        font-size: 12px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      h1 {
        margin: 16px 0 8px;
        font-size: clamp(28px, 4vw, 42px);
      }
      p {
        margin: 0 0 20px;
        color: var(--muted);
        line-height: 1.6;
      }
      code {
        background: #f0e6d8;
        padding: 2px 6px;
        border-radius: 6px;
        font-family: "JetBrains Mono", "Courier New", monospace;
        font-size: 0.95em;
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin: 24px 0;
      }
      .button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 14px 24px;
        border-radius: 999px;
        background: var(--accent);
        color: #fff;
        text-decoration: none;
        font-weight: 600;
        transition: transform 150ms ease, box-shadow 150ms ease;
        box-shadow: 0 16px 24px rgba(14, 111, 106, 0.25);
      }
      .button:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 28px rgba(14, 111, 106, 0.3);
      }
      .details {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 12px;
        margin-top: 8px;
      }
      .details div {
        border: 1px solid #efe1d1;
        border-radius: 14px;
        padding: 12px 14px;
        background: #fffdf8;
      }
      .details span {
        display: block;
        font-size: 12px;
        color: var(--muted);
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 6px;
      }
      .note {
        font-size: 13px;
        color: var(--muted);
        margin-top: 18px;
      }
      .note strong {
        color: var(--accent-2);
      }
      .vm-panel {
        margin-top: 26px;
        padding: 18px;
        border: 1px solid #efe1d1;
        border-radius: 18px;
        background: #fffdf8;
      }
      .vm-panel h2 {
        margin: 0 0 6px;
        font-size: clamp(20px, 2.6vw, 30px);
      }
      .vm-subtitle {
        margin: 0;
        color: var(--muted);
        font-size: 14px;
      }
      .vm-table-wrap {
        margin-top: 12px;
        border: 1px solid #efe1d1;
        border-radius: 14px;
        background: #fff;
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
        background: #fff7ec;
      }
      .vm-table td {
        padding: 10px 12px;
        border-top: 1px solid #efe1d1;
      }
      .vm-table tbody tr:hover {
        background: rgba(212, 127, 42, 0.08);
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
        border-radius: 999px;
        background: var(--accent);
        color: #fff;
        text-decoration: none;
        font-weight: 600;
        font-size: 12px;
        box-shadow: 0 10px 18px rgba(14, 111, 106, 0.2);
        transition: transform 150ms ease, box-shadow 150ms ease;
      }
      .vm-download:hover {
        transform: translateY(-1px);
        box-shadow: 0 14px 22px rgba(14, 111, 106, 0.25);
      }
      .vm-error {
        margin: 12px 0 0;
        color: var(--accent-2);
        font-weight: 600;
      }
      .vm-empty {
        margin: 12px 0 0;
        color: var(--muted);
      }
    </style>
  </head>
  <body>
    <main>
      <span class="badge">RDP Gateway</span>
      <h1>Remote Desktop Gateway</h1>
      <p>Download a preconfigured <code>.rdp</code> file. It targets <code>{{.Target}}</code> and uses gateway <code>{{.Gateway}}</code>.</p>
      <div class="actions">
        <a class="button" href="/{{.Filename}}">Download RDP File</a>
      </div>
      <div class="details">
        <div>
          <span>Gateway Host</span>
          <strong>{{.Gateway}}</strong>
        </div>
        <div>
          <span>Target Address</span>
          <strong>{{.Target}}</strong>
        </div>
      </div>
      <p class="note"><strong>Tip:</strong> Update the target if you want to reach a different workstation.</p>
      <section class="vm-panel">
        <h2>Available VMs</h2>
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
                      <a class="vm-download" href="/{{$.Filename}}?target={{.RDPHost | urlquery}}">Download</a>
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

var indexTemplate = template.Must(template.New("index").Parse(indexHTML))

type indexVM struct {
	Name      string
	IP        string
	RDPHost   string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
}

func renderIndexPage(w http.ResponseWriter, gatewayHost, targetHost string) {
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
			targetHost := vm.PrimaryIP
			if targetHost == "" {
				targetHost = vm.Name
			}
			rdpHost := rdpTargetHost(targetHost)
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
	if err := indexTemplate.Execute(w, data); err != nil {
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
