package auth

import (
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase/apis"
)

// Installs an `/api/me` endpoint
func InstallAPIMeEndpoint(router *echo.Echo) {
	router.GET("/api/me", func(c echo.Context) error {
		if c.Get(apis.ContextAdminKey) != nil {
			return c.JSON(200, c.Get(apis.ContextAdminKey))
		} else {
			return c.JSON(200, c.Get(apis.ContextAuthRecordKey))
		}
	})
}
