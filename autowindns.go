package autowindns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(AutoWinDNS{})
	caddy.RegisterGlobalOption("auto_windns", parseCaddyfileGlobalOption)
}

type AutoWinDNS struct {
	Server        string         `json:"server,omitempty"`
	Username      string         `json:"username,omitempty"`
	Password      string         `json:"password,omitempty"`
	Zone          string         `json:"zone,omitempty"`
	Target        string         `json:"target,omitempty"`
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`
	logger        *zap.Logger
	mutex         sync.Mutex
	ctx           caddy.Context
}

func (AutoWinDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "auto-windns",
		New: func() caddy.Module { return new(AutoWinDNS) },
	}
}

func (a *AutoWinDNS) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	a.ctx = ctx
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(1 * time.Hour)
	}
	return nil
}

func (a *AutoWinDNS) Start() error {
	go a.run()
	return nil
}

func (a *AutoWinDNS) Stop() error {
	return nil
}

func (a *AutoWinDNS) run() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()
	for {
		a.updateCNAMERecords()
		select {
		case <-ticker.C:
			continue
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *AutoWinDNS) updateCNAMERecords() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	hostnames, err := a.getHostnamesFromConfig()
	if err != nil {
		a.logger.Error("failed to get hostnames from config", zap.Error(err))
		return
	}

	for _, hostname := range hostnames {
		alias := strings.Split(hostname, ".")[0]
		if err := a.createCNAMERecord(alias); err != nil {
			a.logger.Error("failed to create CNAME record", zap.String("hostname", hostname), zap.Error(err))
		}
	}
}

func (a *AutoWinDNS) getHostnamesFromConfig() ([]string, error) {
	appModule, err := a.ctx.App("http")
	if err != nil {
		return nil, err
	}
	httpApp := appModule.(*caddyhttp.App)
	var hostnames []string
	for _, srv := range httpApp.Servers {
		for _, route := range srv.Routes {
			for _, ms := range route.MatcherSets {
				for _, matcher := range ms {
					if matchHost, ok := matcher.(caddyhttp.MatchHost); ok {
						hostnames = append(hostnames, matchHost...)
					}
				}
			}
		}
	}
	return hostnames, nil
}

func (a *AutoWinDNS) createCNAMERecord(alias string) error {
	cmd := fmt.Sprintf("Add-DnsServerResourceRecordCName -Name %s -ZoneName %s -HostNameAlias %s", alias, a.Zone, a.Target)
	config := &ssh.ClientConfig{
		User: a.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(a.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", a.Server+":22", config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var output, stderr strings.Builder
	session.Stdout = &output
	session.Stderr = &stderr

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to run command: %w, stderr: %s", err, stderr.String())
	}

	return nil
}

func (a *AutoWinDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return parseCaddyfileGlobalOption(d, a)
}

func parseCaddyfileGlobalOption(d *caddyfile.Dispenser, a interface{}) (interface{}, error) {
	if a == nil {
		a = new(AutoWinDNS)
	}

	app := a.(*AutoWinDNS)
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "server":
				if !d.Args(&app.Server) {
					return nil, d.ArgErr()
				}
			case "username":
				if !d.Args(&app.Username) {
					return nil, d.ArgErr()
				}
			case "password":
				if !d.Args(&app.Password) {
					return nil, d.ArgErr()
				}
			case "zone":
				if !d.Args(&app.Zone) {
					return nil, d.ArgErr()
				}
			case "target":
				if !d.Args(&app.Target) {
					return nil, d.ArgErr()
				}
			case "check_interval":
				var interval string
				if !d.Args(&interval) {
					return nil, d.ArgErr()
				}
				dur, err := time.ParseDuration(interval)
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				app.CheckInterval = caddy.Duration(dur)
			}
		}
	}
	return app, nil
}

var (
	_ caddy.Provisioner     = (*AutoWinDNS)(nil)
	_ caddy.App             = (*AutoWinDNS)(nil)
	_ caddyfile.Unmarshaler = (*AutoWinDNS)(nil)
)
