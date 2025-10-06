package types

type SwaggerConfig struct {
	Title       string
	Path        string
	Description string
	Version     string
	Servers     []SwaggerServer
}
type SwaggerServer struct {
	URL         string
	Description string
}
