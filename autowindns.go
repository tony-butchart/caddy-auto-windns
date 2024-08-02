package autowindns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(AutoWinDNS{})
	httpcaddyfile.RegisterGlobalOption("auto_windns", parseAutoWinDNS)
}

type AutoWinDNS struct {
	Server         string         `json:"server,omitempty"`
	Username       string         `json:"username,omitempty"`
	Password       string         `json:"password,omitempty"`
	Zone           string         `json:"zone,omitempty"`
	Target         string         `json:"target,omitempty"`
	CheckInterval  caddy.Duration `json:"check_interval,omitempty"`
	logger         *zap.Logger
	mutex          sync.Mutex
	ctx            caddy.Context
	createdRecords map[string]bool
}

func parseAutoWinDNS(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(AutoWinDNS)
	err := app.UnmarshalCaddyfile(d)
	if err != nil {
		return nil, err
	}
	return app, nil
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
	a.createdRecords = make(map[string]bool)

	a.logger.Info("AutoWinDNS module provisioned",
		zap.String("server", a.Server),
		zap.String("zone", a.Zone),
		zap.Duration("check_interval", time.Duration(a.CheckInterval)))

	return nil
}

func (a *AutoWinDNS) Start() error {
	a.logger.Info("AutoWinDNS module starting")
	go func() {
		for {
			select {
			case <-a.ctx.Done():
				a.logger.Info("AutoWinDNS context done, stopping updates")
				return
			case <-time.After(time.Duration(a.CheckInterval)):
				a.logger.Info("AutoWinDNS updating CNAME records")
				a.updateCNAMERecords()
			}
		}
	}()
	return nil
}

func (a *AutoWinDNS) Stop() error {
	a.logger.Info("AutoWinDNS module stopping")
	return nil
}

func (a *AutoWinDNS) updateCNAMERecords() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.logger.Info("Fetching hostnames from config")
	hostnames, err := a.getHostnamesFromConfig()
	if err != nil {
		a.logger.Error("Failed to get hostnames from config", zap.Error(err))
		return
	}

	a.logger.Info("Updating CNAME records", zap.Int("count", len(hostnames)))
	for _, hostname := range hostnames {
		alias := strings.Split(hostname, ".")[0]
		if a.createdRecords[alias] {
			a.logger.Debug("CNAME record already exists", zap.String("alias", alias))
			continue
		}
		err := a.createCNAMERecord(alias)
		if err != nil {
			a.logger.Error("Failed to create CNAME record",
				zap.String("hostname", hostname),
				zap.String("alias", alias),
				zap.Error(err))
			continue
		}
		a.createdRecords[alias] = true
		a.logger.Info("Successfully created CNAME record",
			zap.String("hostname", hostname),
			zap.String("alias", alias))
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

	a.logger.Info("Creating CNAME record", zap.String("alias", alias), zap.String("cmd", cmd))

	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		err := a.executeSSHCommand(cmd)
		if err == nil {
			return nil
		}
		a.logger.Warn("Failed to create CNAME record, retrying",
			zap.String("alias", alias),
			zap.Int("retry", retry+1),
			zap.Error(err))
		time.Sleep(time.Second * time.Duration(retry+1))
	}
	return fmt.Errorf("failed to create CNAME record after %d retries", maxRetries)
}

func (a *AutoWinDNS) executeSSHCommand(cmd string) error {
	config := &ssh.ClientConfig{
		User: a.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(a.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	a.logger.Info("Dialing SSH", zap.String("server", a.Server))

	client, err := ssh.Dial("tcp", a.Server+":22", config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %w", err)
	}
	defer client.Close()

	a.logger.Info("Creating SSH session")
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var output, stderr strings.Builder
	session.Stdout = &output
	session.Stderr = &stderr

	a.logger.Info("Running SSH command", zap.String("cmd", cmd))
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to run command: %w, stderr: %s", err, stderr.String())
	}

	a.logger.Info("SSH command output", zap.String("output", output.String()))

	return nil
}

func (a *AutoWinDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Server = d.Val()
			case "username":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Username = d.Val()
			case "password":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Password = d.Val()
			case "zone":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Zone = d.Val()
			case "target":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Target = d.Val()
			case "check_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid duration: %v", err)
				}
				a.CheckInterval = caddy.Duration(dur)
			default:
				return d.Errf("unknown subdirective %s", d.Val())
			}
		}
	}

	// Validate required fields
	if a.Server == "" {
		return d.Err("server is required")
	}
	if a.Username == "" {
		return d.Err("username is required")
	}
	if a.Password == "" {
		return d.Err("password is required")
	}
	if a.Zone == "" {
		return d.Err("zone is required")
	}
	if a.Target == "" {
		return d.Err("target is required")
	}

	a.logger.Info("Unmarshaled AutoWinDNS configuration",
		zap.String("server", a.Server),
		zap.String("username", a.Username),
		zap.String("zone", a.Zone),
		zap.String("target", a.Target),
		zap.Duration("check_interval", time.Duration(a.CheckInterval)))

	return nil
}

var (
	_ caddy.Provisioner     = (*AutoWinDNS)(nil)
	_ caddy.App             = (*AutoWinDNS)(nil)
	_ caddyfile.Unmarshaler = (*AutoWinDNS)(nil)
)
