package auth

import (
	"fmt"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tokens"
)

/*
Header auth enables you to authenticate users and admins via HTTP headers.
This is useful when you want to authenticate users via a proxy server.
For example, you can use [caddy](https://caddyserver.com/) to authenticate
users via SAML and pass the user's email to the backend via a header.
*/
func InstallHeaderAuth(app core.App, router *echo.Echo, config HeaderAuthConfig) {
	if !config.IsValid() {
		return
	}
	router.Pre(
		authViaHeader(app, config), // authenticate admin & user requests

		// these are needed because echo doesn't allow us to overwrite endpoints
		overwriteAdminEmailAuth(app), // overwrite admin email auth endpoint: /api/admins/auth-via-email
		overwriteUserEmailAuth(app),  // overwrite user email auth endpoint: /api/users/auth-via-email
	)
}

func authenticateUser(app core.App, c echo.Context, config HeaderAuthConfig) *models.Record {
	email := config.GetEmailFromHeader(c.Request().Header)
	name := config.GetNameFromHeader(c.Request().Header)
	users, _ := app.Dao().FindCollectionByNameOrId("users")
	user, err := app.Dao().FindAuthRecordByEmail("users", email)

	if err != nil {
		if config.AutoCreateUser && email != "" {
			// create user
			user = models.NewRecord(users)
			user.SetEmail(email)
			user.SetVerified(true)
			user.Set("name", name)
			user.RefreshTokenKey()
			app.Dao().Save(user)

			fmt.Println("User", user.GetString("email"), "created")
		} else {
			return nil
		}
	}
	return user
}

func authViaHeader(app core.App, config HeaderAuthConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// if request starts with /api/*
			if strings.HasPrefix(c.Request().RequestURI, "/api/") {
				email := config.GetEmailFromHeader(c.Request().Header)
				if email != "" {
					// check for admin
					admin, _ := app.Dao().FindAdminByEmail(email)
					if admin != nil {
						c.Set("admin", admin)
					}

					// check for user
					if user := authenticateUser(app, c, config); user != nil {
						c.Set("user", user)
					}
				}
			}

			return next(c)
		}
	}
}

func overwriteAdminEmailAuth(app core.App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == "POST" && c.Request().RequestURI == "/api/admins/auth-with-password" {
				admin, _ := c.Get(apis.ContextAdminKey).(*models.Admin)
				if admin == nil {
					return next(c)
				}

				token, tokenErr := tokens.NewAdminAuthToken(app, admin)
				if tokenErr != nil {
					return next(c)
				}

				event := &core.AdminAuthEvent{
					HttpContext: c,
					Admin:       admin,
					Token:       token,
				}

				return app.OnAdminAuthRequest().Trigger(event, func(e *core.AdminAuthEvent) error {
					return e.HttpContext.JSON(200, map[string]any{
						"token": e.Token,
						"admin": e.Admin,
					})
				})
			}

			return next(c)
		}
	}
}

func overwriteUserEmailAuth(app core.App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == "POST" && c.Request().RequestURI == "/api/collections/users/auth-with-password" {
				user, _ := c.Get("user").(*models.Record)
				if user == nil {
					return next(c)
				}

				token, tokenErr := tokens.NewRecordAuthToken(app, user)
				if tokenErr != nil {
					return next(c)
				}

				event := &core.RecordAuthEvent{
					HttpContext: c,
					Record:      user,
					Token:       token,
				}

				return app.OnRecordAuthRequest().Trigger(event, func(e *core.RecordAuthEvent) error {
					return e.HttpContext.JSON(200, map[string]any{
						"token":  e.Token,
						"record": e.Record,
					})
				})
			}

			return next(c)
		}
	}
}
