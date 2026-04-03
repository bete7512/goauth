//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
)

// User's own audit endpoints

func TestAudit_MyAuditLogs(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "audit@example.com", "Test1234", "Audit User")

	w := h.JSONGet(handler, "/auth/me/audit", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "me/audit: %s", w.Body.String())
}

func TestAudit_MyLoginLogs(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "audit@example.com", "Test1234", "Audit User")

	w := h.JSONGet(handler, "/auth/me/audit/logins", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "me/audit/logins: %s", w.Body.String())
}

func TestAudit_MyChangeLogs(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "audit@example.com", "Test1234", "Audit User")

	w := h.JSONGet(handler, "/auth/me/audit/changes", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "me/audit/changes: %s", w.Body.String())
}

func TestAudit_MySecurityLogs(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "audit@example.com", "Test1234", "Audit User")

	w := h.JSONGet(handler, "/auth/me/audit/security", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "me/audit/security: %s", w.Body.String())
}

func TestAudit_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)

	w := h.JSONGet(handler, "/auth/me/audit")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// Admin audit endpoints (require admin role)

func TestAudit_AdminList_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/admin/audit", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "non-admin should get 403")
}

func TestAudit_AdminUserAudit_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/admin/audit/users/some-id", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAudit_AdminActionAudit_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/admin/audit/actions/login", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAudit_AdminCleanup_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/admin/audit/cleanup", nil, h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}
