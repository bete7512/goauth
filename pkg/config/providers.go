package config

type ProvidersConfig struct {
	Enabled   []AuthProvider
	Google    ProviderConfig
	GitHub    ProviderConfig
	Facebook  ProviderConfig
	Microsoft ProviderConfig
	Apple     ProviderConfig
	Twitter   ProviderConfig
	LinkedIn  ProviderConfig
	Discord   ProviderConfig
	Spotify   ProviderConfig
	Slack     ProviderConfig
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	TenantId     *string
}
