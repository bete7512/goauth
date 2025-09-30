package oauth_service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

func (s *OAuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*dto.OAuthUserInfo, *types.GoAuthError) {
	url := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return nil, types.NewInternalError(fmt.Sprintf("failed to get user info: %s", string(body)))
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}

	err = json.Unmarshal(body, &googleUser)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	firstName := googleUser.GivenName
	if firstName == "" {
		firstName = googleUser.Name
	}

	return &dto.OAuthUserInfo{
		ProviderID:    googleUser.ID,
		Email:         googleUser.Email,
		FirstName:     firstName,
		LastName:      googleUser.FamilyName,
		Avatar:        &googleUser.Picture,
		Provider:      dto.Google,
		VerifiedEmail: googleUser.VerifiedEmail,
	}, nil
}
