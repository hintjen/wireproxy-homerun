//go:build !android

package main

import "github.com/landlock-lsm/go-landlock/landlock"

// restrictPaths applies wireproxy's Landlock sandbox.
//
// Split out only so Android can opt out — see landlock_android.go for why.
func restrictPaths(rules ...landlock.Rule) error {
	return landlock.V1.BestEffort().RestrictPaths(rules...)
}

// restrictNet applies wireproxy's Landlock network sandbox.
func restrictNet(rules ...landlock.Rule) error {
	return landlock.V4.BestEffort().RestrictNet(rules...)
}
