package main

import (
	"html/template"
	"net"
	"net/http"
	"strings"
)

const (
	defaultRDPAddress = "workstation:3389"
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
    </main>
  </body>
</html>
`

var indexTemplate = template.Must(template.New("index").Parse(indexHTML))

func renderIndexPage(w http.ResponseWriter, gatewayHost, targetHost string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Gateway  string
		Target   string
		Filename string
	}{
		Gateway:  gatewayHost,
		Target:   targetHost,
		Filename: rdpFilename,
	}
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
		return
	}
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
	write("gatewayprofileusagemethod:i:0")
	write("promptcredentialonce:i:0")
	write("authentication level:i:2")
	write("use redirection server name:i:1")
	return b.String()
}
