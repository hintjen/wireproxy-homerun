package wireproxy

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

// capture collects everything the device logs, so a test can assert on lines
// that would otherwise go to a process stderr nobody reads.
type capture struct {
	mu    sync.Mutex
	lines []string
}

func (c *capture) logger() *device.Logger {
	record := func(format string, args ...any) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.lines = append(c.lines, fmt.Sprintf(format, args...))
	}
	return &device.Logger{Verbosef: record, Errorf: record}
}

func (c *capture) contains(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range c.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

// The device is brought up and torn down for each of these, so keep the
// fixture minimal: a peer that will never answer is fine, because the point is
// what gets logged on the way, not whether a handshake completes.
func startForTest(t *testing.T, logger *device.Logger) *VirtualTun {
	t.Helper()
	conf, err := ParseConfigString(sampleConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}
	tun, err := StartWireguardWithLogger(conf, logger)
	if err != nil {
		t.Fatalf("StartWireguardWithLogger: %v", err)
	}
	t.Cleanup(func() {
		tun.Dev.Close()
	})
	return tun
}

// The reason the patch exists: a consumer must be able to see the device's
// output rather than have it written to a stderr it does not own.
func TestStartWireguardWithLoggerDeliversLines(t *testing.T) {
	c := &capture{}
	startForTest(t, c.logger())

	if c.count() == 0 {
		t.Fatal("the logger received nothing; device output is not reaching the caller")
	}
	// wireguard-go announces the interface as it comes up. The exact wording is
	// upstream's, so match on something structural rather than a full line.
	if !c.contains("UAPI") && !c.contains("peer") && !c.contains("device") {
		t.Errorf("captured lines look wrong: %v", c.lines)
	}
}

// nil must be silence, not a nil dereference inside the device.
func TestStartWireguardWithNilLoggerIsSilent(t *testing.T) {
	startForTest(t, nil)
}

// The CLI's entry point must keep working unchanged.
func TestStartWireguardStillWorks(t *testing.T) {
	conf, err := ParseConfigString(sampleConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}
	tun, err := StartWireguard(conf, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("StartWireguard: %v", err)
	}
	defer tun.Dev.Close()

	if tun.Tnet == nil || tun.Dev == nil {
		t.Error("StartWireguard returned an incomplete VirtualTun")
	}
}
