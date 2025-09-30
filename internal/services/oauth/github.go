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

func (s *OAuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (*dto.OAuthUserInfo, *types.GoAuthError) {
	url := "https://api.github.com/user"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

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

	var githubUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	err = json.Unmarshal(body, &githubUser)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	// If email is private, fetch it separately
	if githubUser.Email == "" {
		email, err := s.getGitHubPrimaryEmail(ctx, accessToken)
		if err != nil {
			return nil, types.NewInternalError(err.Error())
		}
		githubUser.Email = email
	}

	providerID := fmt.Sprintf("%d", githubUser.ID)
	firstName := githubUser.Name
	if firstName == "" {
		firstName = githubUser.Login
	}

	return &dto.OAuthUserInfo{
		ProviderID:    providerID,
		Email:         githubUser.Email,
		FirstName:     firstName,
		LastName:      "", // GitHub doesn't provide separated name fields
		Avatar:        &githubUser.AvatarURL,
		Provider:      dto.GitHub,
		VerifiedEmail: true, // GitHub emails are typically verified
	}, nil
}

func (s *OAuthService) getGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, *types.GoAuthError) {
	url := "https://api.github.com/user/emails"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", types.NewInternalError(err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", types.NewInternalError(err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", types.NewInternalError(err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return "", types.NewInternalError(fmt.Sprintf("failed to get emails: %s", string(body)))
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	err = json.Unmarshal(body, &emails)
	if err != nil {
		return "", types.NewInternalError(err.Error())
	}

	// Find primary email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// If no primary verified email, return the first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", types.NewInternalError("no verified email found")
}
