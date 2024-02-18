package main

import "testing"

func BenchmarkLiteralTest(b *testing.B) {
	b.ResetTimer()

	b.Run("fingerprint", func(b *testing.B) {
		ips := []string{"10.12.78.221", "10.129.112.8", "10.129.112.11", "10.12.77.110", "10.12.77.111", "10.12.77.107"}
		doScan(ips, "80,443,9990")
	})
}
