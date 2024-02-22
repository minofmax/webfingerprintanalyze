package main

import "testing"

func TestFeatures(t *testing.T) {
	ips := []string{"10.12.78.221", "10.129.112.8", "10.129.112.11", "10.12.77.110", "10.12.77.111", "10.12.77.107"}

	t.Run("fingerprint", func(t *testing.T) {
		doScan(ips, "1-10000")
	})
}
