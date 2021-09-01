package main

// Config store http-cli configuration
type Config struct {
	LogLevel string
	Method   string
	Body     string
	HexDump  bool
	URL      string
	// credentials
	Username string
	Password string
	// SSPI auth package
	Package string
}

func NewConfig() *Config {
	return &Config{
		Method:   "GET",
		Package:  "Negotiate",
		LogLevel: "info",
	}
}
