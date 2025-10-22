package web

import (
	"embed"
	"html/template"
	"sync"
)

//go:embed templates/login.html
var loginTemplateFS embed.FS

var (
	loginOnce sync.Once
	loginTpl  *template.Template
	loginErr  error
)

// LoginTemplate returns the parsed HTML template for the login screen.
func LoginTemplate() (*template.Template, error) {
	loginOnce.Do(func() {
		loginTpl, loginErr = template.ParseFS(loginTemplateFS, "templates/login.html")
	})
	return loginTpl, loginErr
}
