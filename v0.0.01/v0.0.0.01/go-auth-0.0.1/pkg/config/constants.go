package config

type ModuleName string

const (
	CoreModule      ModuleName = "core"
	TwoFactorModule ModuleName = "twofactor"
	OAuthModule     ModuleName = "oauth"
	MagicLinkModule ModuleName = "magiclink"
)
