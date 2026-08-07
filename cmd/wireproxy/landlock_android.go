//go:build android

package main

import "github.com/landlock-lsm/go-landlock/landlock"

// restrictPaths does nothing on Android, because attempting it kills the
// process.
//
// Landlock probes its own ABI version with syscall 444
// (`landlock_create_ruleset`). Android's seccomp filter for app processes does
// not allow that syscall, and its policy is to raise **SIGSYS** rather than
// return ENOSYS — so the probe never gets to fail gracefully. `BestEffort()`
// cannot help: it degrades when Landlock is *absent*, and from its point of
// view the kernel here supports it fine, right up until the process is killed.
//
// The symptom is wireproxy dying roughly 50ms after spawning, with
// "SIGSYS: bad system call" and a Go traceback through
// landlock.getSupportedABIVersion — no wireproxy log line, no config error,
// nothing pointing at a sandbox.
//
// Dropping it costs little here. Landlock confines a long-lived daemon on a
// shared machine; on Android the app is already confined far more tightly by
// the SELinux domain and app sandbox it runs in, which is what makes the
// syscall unavailable in the first place.
func restrictPaths(_ ...landlock.Rule) error {
	return nil
}

// restrictNet is a no-op for the same reason as restrictPaths: every entry
// point into Landlock probes the ABI version first, so the network sandbox
// dies on exactly the same blocked syscall as the filesystem one.
func restrictNet(_ ...landlock.Rule) error {
	return nil
}
