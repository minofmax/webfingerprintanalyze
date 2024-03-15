package main

import "testing"

func TestFeatures(t *testing.T) {
	ips := []string{}

	t.Run("fingerprint", func(t *testing.T) {
		doScan(ips, "80,443,9990")
	})
}
