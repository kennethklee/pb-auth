package plugin

import (
	"github.com/fatih/color"
	auth "github.com/kennethklee/pb-auth"
	"github.com/kennethklee/xpb"
	"github.com/pocketbase/pocketbase/core"
)

var VERSION = "1.4.0"

type Plugin struct{}

func (p *Plugin) Info() xpb.PluginInfo {

	return xpb.PluginInfo{
		Name:        "HeaderAuth",
		Version:     VERSION,
		Description: "Authenticate users and admins via HTTP headers",
	}
}

func (p *Plugin) OnPreload() error {
	return nil
}

func (p *Plugin) OnLoad(app core.App) error {
	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		bold := color.New(color.Bold).Add(color.FgGreen)
		bold.Println("> Auth Config")
		authConfig := auth.HeaderAuthConfigFromEnv()
		authConfig.AdminLogin = true // Need this to manage users & servers
		auth.InstallHeaderAuth(e.App, e.Router, auth.HeaderAuthConfigFromEnv())
		return nil
	})
	return nil
}

func init() {}
	xpb.Register(&Plugin{})
}
