package main

import (
	auth "github.com/kennethklee/pb-auth"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	var app = pocketbase.New()

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		auth.InstallHeaderAuth(app, e.Router, auth.HeaderAuthConfig{
			NameHeader:     "X-Forwarded-User",
			EmailHeader:    "X-Forwarded-Email",
			AutoCreateUser: true,

			ForceEmail:    "test@test.com",
			ForceName:     "Test Admin",
			ForceUsername: "testadmin",
		})
		auth.InstallAPIMeEndpoint(e.Router)
		return nil
	})

	if err := app.Start(); err != nil {
		panic(err)
	}
}
