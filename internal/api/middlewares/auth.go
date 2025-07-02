package middlewares

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
)

func (m *Middleware) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if userID == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user id not found in request"))
			return
		}
		user, err := m.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if user == nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user not found"))
			return
		}
		if user.IsAdmin == nil || !*user.IsAdmin {
			utils.RespondWithError(w, http.StatusForbidden, "forbidden", errors.New("user is not an admin"))
			return
		}
		ctx := context.WithValue(r.Context(), config.UserIDKey, userID)
		ctx = context.WithValue(ctx, config.IsAdminKey, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// AuthMiddleware validates user authentication but doesn't require admin privileges
func (m *Middleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("AuthMiddleware")
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if userID == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user id not found in request"))
			return
		}

		// Add user ID to context for downstream handlers
		ctx := context.WithValue(r.Context(), config.UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
