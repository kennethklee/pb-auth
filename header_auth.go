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

func authenticateUser(app core.App, c echo.Context, config HeaderAuthConfig) *models.User {
	email := config.GetEmailFromHeader(c.Request().Header)
	user, err := app.Dao().FindUserByEmail(email)
	if err != nil {
		if config.AutoCreateUser && email != "" {
			// create user
			user = &models.User{}
			user.Email = email
			user.Verified = true
			user.RefreshTokenKey()
			app.Dao().SaveUser(user)

			fmt.Println("User", user.Email, "created")
		} else {
			return nil
		}
	}

	if config.AutoCreateUser {
		// update user's name if changed
		name := config.GetNameFromHeader(c.Request().Header)
		if config.ForceName != "" {
			name = config.ForceName
		}
		if name != "" && name != user.Profile.GetStringDataValue("name") {
			user.Profile.SetDataValue("name", name)
			app.Dao().SaveRecord(user.Profile)

			fmt.Println("User", user.Email, "profile name updated to", name)
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
						c.Set(apis.ContextAdminKey, admin)
					}

					// check for user
					if user := authenticateUser(app, c, config); user != nil {
						c.Set(apis.ContextUserKey, user)
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
			if c.Request().Method == "POST" && c.Request().RequestURI == "/api/admins/auth-via-email" {
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
			if c.Request().Method == "POST" && c.Request().RequestURI == "/api/users/auth-via-email" {
				user, _ := c.Get(apis.ContextUserKey).(*models.User)
				if user == nil {
					return next(c)
				}

				token, tokenErr := tokens.NewUserAuthToken(app, user)
				if tokenErr != nil {
					return next(c)
				}

				event := &core.UserAuthEvent{
					HttpContext: c,
					User:        user,
					Token:       token,
				}

				return app.OnUserAuthRequest().Trigger(event, func(e *core.UserAuthEvent) error {
					return e.HttpContext.JSON(200, map[string]any{
						"token": e.Token,
						"user":  e.User,
					})
				})
			}

			return next(c)
		}
	}
}
