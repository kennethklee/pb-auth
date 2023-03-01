package main

import (
	auth "github.com/kennethklee/pb-auth"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// My lazy manual test

func main() {
	var app = pocketbase.New()

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		auth.InstallHeaderAuth(app, e.Router, auth.HeaderAuthConfig{
			NameHeader:  "X-Forwarded-User",
			EmailHeader: "X-Forwarded-Email",
			AdminLogin:  false,

			AutoCreateUser: true,
			AutoCreateFieldMapping: map[string]string{
				"username": "X-Forwarded-Username",
			},

			ForceEmail: "test@test.com",
			ForceName:  "Test Admin",
			// ForceUsername: "testadmin",
		})
		auth.InstallAPIMeEndpoint(e.Router)
		return nil
	})

	if err := app.Start(); err != nil {
		panic(err)
	}
}
