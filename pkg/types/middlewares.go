package types

// MiddlewareName identifies a registered middleware. Routes list the
// middleware they require by name.
type MiddlewareName string

// Built-in middleware names.
const (
	MiddlewareAuth      MiddlewareName = "core.auth"
	MiddlewareAdminAuth MiddlewareName = "admin.auth"
	MiddlewareCSRF      MiddlewareName = "csrf.csrf"
	MiddlewareCaptcha   MiddlewareName = "captcha.verify"
	MiddlewareOrgAuth   MiddlewareName = "org.auth"
	MiddlewareRateLimit MiddlewareName = "ratelimit.limit"
)
