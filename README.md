Pocketbase Auth Library
=======================

Currently supports the following:

* Header Auth
* `/api/me` endpoint for current user

Installation
------------

```
go get github.com/kennethklee/pb-auth
```

Usage
-----

```go
package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	auth "github.com/kennethklee/pb-auth"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	pb := pocketbase.New()

	pb.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		bold := color.New(color.Bold).Add(color.FgGreen)
		bold.Println("> Auth Config")
		headerAuthConfig := getHeaderAuthConfig()
		if headerAuthConfig.IsValid() {
			fmt.Println("  - Header auth enabled")
		} else {
			fmt.Println("  - Header auth disabled")
		}

		auth.InstallHeaderAuth(e.App, e.Router, headerAuthConfig)
		auth.InstallAPIMeEndpoint(e.Router)

		return nil
	})

	pb.Start()
}

func getHeaderAuthConfig() auth.HeaderAuthConfig {
	headerAuthConfig := auth.HeaderAuthConfig{
		EmailHeader:    "X-Auth-Email",
		NameHeader:     "X-Auth-Name",
		AutoCreateUser: true,
	}

	// when not running `APP_ENV=production`, only local, force email and name
	if os.Getenv("APP_ENV") != "production" {
		headerAuthConfig.ForceEmail = "local@mycompany.com"
		headerAuthConfig.ForceName = "Local User"
	}

	return headerAuthConfig
}
```