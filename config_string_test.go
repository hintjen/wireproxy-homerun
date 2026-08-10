package wireproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config in the shape homerun-core renders: one interface, one peer, one
// inbound TCP forward.
//
// The endpoint is a literal address rather than a hostname because parsing
// resolves it (resolveIPPAndPort), so a name would make these tests depend on
// DNS. 192.0.2.0/24 is TEST-NET-1: reserved, unroutable, and guaranteed never
// to belong to anyone.
const sampleConfig = `[Interface]
PrivateKey = OMhFP0Xt3AKk7oNXFVpXsPqFPRhKa5PHSCiKX2h2XHo=
Address = 10.0.0.2/24
MTU = 1280

[Peer]
PublicKey = 7ZKMOxBmLLXCKCXeGgLLW1LtRYKPvNvhSTk0kPYWUXA=
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.0.0.1/32
PersistentKeepalive = 30

[TCPServerTunnel]
ListenPort = 25565
Target = 127.0.0.1:25565
`

func TestParseConfigStringMatchesParseConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireproxy.conf")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		t.Fatalf("could not write the fixture: %v", err)
	}

	fromFile, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	fromString, err := ParseConfigString(sampleConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}

	// The point of the patch is that these are the same config, so the
	// in-memory path cannot quietly diverge from the one the CLI uses.
	if fromString.Device.SecretKey != fromFile.Device.SecretKey {
		t.Error("the private key differs between the two parses")
	}
	if len(fromString.Device.Peers) != len(fromFile.Device.Peers) {
		t.Fatalf("peer count differs: %d vs %d",
			len(fromString.Device.Peers), len(fromFile.Device.Peers))
	}
	if fromString.Device.Peers[0].PublicKey != fromFile.Device.Peers[0].PublicKey {
		t.Error("the peer public key differs")
	}
	if fromString.Device.MTU != fromFile.Device.MTU {
		t.Errorf("MTU differs: %d vs %d", fromString.Device.MTU, fromFile.Device.MTU)
	}
	if len(fromString.Routines) != len(fromFile.Routines) {
		t.Errorf("routine count differs: %d vs %d",
			len(fromString.Routines), len(fromFile.Routines))
	}
}

// The forward has to survive, or the tunnel comes up carrying nothing — which
// looks like a working server nobody can reach.
func TestParseConfigStringKeepsTheForward(t *testing.T) {
	conf, err := ParseConfigString(sampleConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}
	if len(conf.Routines) != 1 {
		t.Fatalf("expected one routine, got %d", len(conf.Routines))
	}
	tunnel, ok := conf.Routines[0].(*TCPServerTunnelConfig)
	if !ok {
		t.Fatalf("expected a TCPServerTunnelConfig, got %T", conf.Routines[0])
	}
	if tunnel.ListenPort != 25565 {
		t.Errorf("ListenPort = %d, want 25565", tunnel.ListenPort)
	}
	if tunnel.Target != "127.0.0.1:25565" {
		t.Errorf("Target = %q, want 127.0.0.1:25565", tunnel.Target)
	}
}

// A path is not a config. Without this check a caller that mixed the two up
// would get "no [Interface] section" rather than anything that points at the
// mistake — and go-ini would happily treat the filename as content.
func TestParseConfigStringRejectsEmptyInput(t *testing.T) {
	for _, empty := range []string{"", "   ", "\n\t\n"} {
		if _, err := ParseConfigString(empty); err == nil {
			t.Errorf("empty input %q must be an error", empty)
		}
	}
}

func TestParseConfigStringReportsBadConfig(t *testing.T) {
	if _, err := ParseConfigString("[Interface]\nPrivateKey = not-base64\n"); err == nil {
		t.Error("an unparseable key must be an error")
	}
}

// The whole reason for the patch: nothing had to touch the disk.
func TestParseConfigStringWritesNothing(t *testing.T) {
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not read the temp dir: %v", err)
	}

	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	if _, err := ParseConfigString(sampleConfig); err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not re-read the temp dir: %v", err)
	}
	if len(after) != len(before) {
		var names []string
		for _, e := range after {
			names = append(names, e.Name())
		}
		t.Errorf("parsing a string left files behind: %s", strings.Join(names, ", "))
	}
}
