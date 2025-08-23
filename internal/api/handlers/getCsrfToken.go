package handlers

// // HandleGetCSRFToken handles getting CSRF token
// func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet {
// 		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
// 		return
// 	}

// 	// Call service
// 	if err := h.authService.GetCSRFToken(r.Context()); err != nil {
// 		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
// 		return
// 	}

// 	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token generated"})
// }
