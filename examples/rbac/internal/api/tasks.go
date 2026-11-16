package api

import "net/http"

func (a *API) completeTask(w http.ResponseWriter, r *http.Request) {
	t, err := a.store.CompleteTask(r.PathValue("id"))
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}
