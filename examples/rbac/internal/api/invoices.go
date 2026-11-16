package api

import (
	"net/http"
	"strings"
)

func (a *API) listInvoices(w http.ResponseWriter, r *http.Request) {
	orgID := caller(r).OrganizationID
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "sign in to an organization first: POST /auth/org/switch")
		return
	}
	writeJSON(w, http.StatusOK, a.store.InvoicesOf(orgID))
}

type invoiceRequest struct {
	Customer    string `json:"customer"`
	AmountCents int64  `json:"amount_cents"`
}

func (a *API) createInvoice(w http.ResponseWriter, r *http.Request) {
	who := caller(r)
	if who.OrganizationID == "" {
		writeError(w, http.StatusBadRequest, "sign in to an organization first: POST /auth/org/switch")
		return
	}
	var req invoiceRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Customer) == "" || req.AmountCents <= 0 {
		writeError(w, http.StatusBadRequest, "customer and a positive amount_cents are required")
		return
	}
	writeJSON(w, http.StatusCreated, a.store.AddInvoice(who.OrganizationID, req.Customer, req.AmountCents, who.UserID))
}

func (a *API) approveInvoice(w http.ResponseWriter, r *http.Request) {
	inv, err := a.store.ApproveInvoice(r.PathValue("id"), caller(r).UserID)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (a *API) billingSummary(w http.ResponseWriter, r *http.Request) {
	invoices := a.store.InvoicesOf(r.PathValue("orgId"))
	var total, approved int64
	for _, inv := range invoices {
		total += inv.AmountCent
		if inv.ApprovedAt != nil {
			approved += inv.AmountCent
		}
	}
	writeJSON(w, http.StatusOK, map[string]int64{"invoices": int64(len(invoices)), "total_cents": total, "approved_cents": approved})
}
