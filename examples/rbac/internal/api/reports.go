package api

import "net/http"

func (a *API) usageReport(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.store.Stats())
}
