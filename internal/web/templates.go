package web

import (
	"bytes"
	"html/template"
)

type PageData struct {
	Title       string
	Message     string
	Locked      bool
	Remaining   int
	LockSeconds int
	Success     bool
}

var pageTpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{.Title}}</title>
    <style>
        body { font-family: system-ui, sans-serif; background-color: #111827; color: #f9fafb; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .card { background-color: #1f2937; padding: 2.5rem; border-radius: 0.75rem; box-shadow: 0 10px 40px rgba(15, 23, 42, 0.6); width: min(400px, 90vw); }
        h1 { margin-top: 0; font-size: 1.5rem; }
        p { line-height: 1.6; }
        form { margin-top: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
        input[type="password"] { width: 100%; padding: 0.75rem; border-radius: 0.5rem; border: 1px solid #374151; background-color: #111827; color: #f9fafb; }
        button { margin-top: 1rem; padding: 0.75rem 1.25rem; border: none; border-radius: 0.5rem; background-color: #2563eb; color: white; font-weight: 600; cursor: pointer; width: 100%; }
        button:hover { background-color: #1d4ed8; }
        .message { margin-top: 1rem; padding: 0.75rem; border-radius: 0.5rem; background-color: #b91c1c; color: #fee2e2; }
        .success { background-color: #065f46; color: #d1fae5; }
    </style>
</head>
<body>
    <div class="card">
        <h1>{{.Title}}</h1>
        {{if .Success}}
            <p>Authentication successful. You may close this window.</p>
        {{else if .Locked}}
            <p>Too many incorrect attempts. Please wait {{.LockSeconds}} seconds before trying again.</p>
        {{else}}
            <p>Enter the secure access password to continue.</p>
            <p>You have {{.Remaining}} attempt{{if eq .Remaining 1}} left{{else}}s left{{end}}.</p>
            <form method="POST" action="/login">
                <label for="password">Security password</label>
                <input type="password" id="password" name="password" autofocus required />
                <button type="submit">Submit</button>
            </form>
        {{end}}
        {{if .Message}}
            <div class="message {{if .Success}}success{{end}}">{{.Message}}</div>
        {{end}}
    </div>
</body>
</html>`))

// RenderPage renders the HTML interface based on the provided data.
func RenderPage(data PageData) (string, error) {
	buf := &bytes.Buffer{}
	if data.Title == "" {
		data.Title = "sshwebdoor"
	}
	if err := pageTpl.Execute(buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
