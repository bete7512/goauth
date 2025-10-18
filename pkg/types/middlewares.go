package types

type MiddlewareName string

const (
	MiddlewareAuth      MiddlewareName = "core.auth"
	MiddlewareAdminAuth MiddlewareName = "admin.auth"
	MiddlewareCSRF      MiddlewareName = "csrf.csrf"
	MiddlewareCaptcha   MiddlewareName = "captcha.verify"
)
