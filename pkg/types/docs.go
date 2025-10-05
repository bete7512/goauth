package types

type SwaggerConfig struct {
	Title       string
	Description string
	Version     string
	Servers     []SwaggerServer
}
type SwaggerServer struct {
	URL         string
	Description string
}
