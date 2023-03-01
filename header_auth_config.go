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

	// Checks for admin users first
	AdminLogin bool

	// If true, automatically create a user if they don't exist.
	AutoCreateUser bool

	// If AutoCreateUser is true, this is a map of the user's fields to the header
	AutoCreateFieldMapping map[string]string

	// Dev only: Force the email address to this value.
	ForceEmail string

	// Dev only: Force the name to this value.
	ForceName string

	// Dev only: Force the username to this value.
	ForceUsername string
}

func HeaderAuthConfigFromEnv() HeaderAuthConfig {
	return HeaderAuthConfig{
		EmailHeader: os.Getenv("HEADER_AUTH_EMAIL"),
		NameHeader:  os.Getenv("HEADER_AUTH_NAME"),
		AdminLogin:  os.Getenv("HEADER_AUTH_ADMIN_LOGIN") != "",

		AutoCreateUser: os.Getenv("AUTO_CREATE_USER") != "",
		AutoCreateFieldMapping: map[string]string{
			"username": os.Getenv("HEADER_AUTH_USERNAME"),
		},

		// Development only options
		ForceEmail:    os.Getenv("FORCE_EMAIL"),
		ForceName:     os.Getenv("FORCE_NAME"),
		ForceUsername: os.Getenv("FORCE_USERNAME"),
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

func (config *HeaderAuthConfig) GetFieldsFromHeader(reqHeader http.Header) map[string]string {
	fields := make(map[string]string)
	for field, header := range config.AutoCreateFieldMapping {
		fields[field] = reqHeader.Get(header)
	}

	if config.ForceUsername != "" {
		fields["username"] = config.ForceUsername
	}
	return fields
}
