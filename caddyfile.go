package autowindns

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("autowindns", parseAutoWinDNS)
}

func parseAutoWinDNS(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(AutoWinDNS)

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "server":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Server = d.Val()
			case "username":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Username = d.Val()
			case "password":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Password = d.Val()
			case "zone":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Zone = d.Val()
			case "target":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Target = d.Val()
			case "check_interval":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				app.CheckInterval = caddy.Duration(dur)
			default:
				return nil, d.Errf("unknown subdirective %s", d.Val())
			}
		}
	}

	// Validate required fields
	if app.Server == "" {
		return nil, d.Err("server is required")
	}
	if app.Username == "" {
		return nil, d.Err("username is required")
	}
	if app.Password == "" {
		return nil, d.Err("password is required")
	}
	if app.Zone == "" {
		return nil, d.Err("zone is required")
	}
	if app.Target == "" {
		return nil, d.Err("target is required")
	}

	return httpcaddyfile.App{
		Name:  "autowindns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
