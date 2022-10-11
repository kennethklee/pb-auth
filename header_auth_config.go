package auth

import (
	"net/http"
	"os"
)

type HeaderAuthConfig struct {
	// The header name that contains the user's email address.
	EmailHeader string

	// The header name that contains the user's name.
	NameHeader string

	// If true, automatically create a user if they don't exist.
	AutoCreateUser bool

	// Dev only: Force the email address to this value.
	ForceEmail string

	// Dev only: Force the name to this value.
	ForceName string
}

func HeaderAuthConfigFromEnv() HeaderAuthConfig {
	return HeaderAuthConfig{
		EmailHeader:    os.Getenv("HEADER_AUTH_EMAIL"),
		NameHeader:     os.Getenv("HEADER_AUTH_NAME"),
		AutoCreateUser: os.Getenv("AUTO_CREATE_USER") != "",

		// Development only options
		ForceEmail: os.Getenv("FORCE_EMAIL"),
		ForceName:  os.Getenv("FORCE_NAME"),
	}
}

func (c HeaderAuthConfig) IsValid() bool {
	// Check for valid configs
	if c.EmailHeader != "" && c.NameHeader != "" {
		return true
	}

	// Check for development only options
	if c.ForceEmail != "" && c.ForceName != "" {
		return true
	}

	return false
}

func (config *HeaderAuthConfig) GetNameFromHeader(reqHeader http.Header) string {
	name := reqHeader.Get(config.NameHeader)

	if config.ForceName != "" {
		name = config.ForceName
	}
	return name
}

func (config *HeaderAuthConfig) GetEmailFromHeader(reqHeader http.Header) string {
	email := reqHeader.Get(config.EmailHeader)

	if config.ForceEmail != "" {
		email = config.ForceEmail
	}
	return email
}
