# web fingerprint analyze

## Description

```
Based on naabu and httpx to do port scan and fingerprint analyze
```

## How To Use
```go
func main() {
	ips := []string{"1.1.1.1", "10.0.0.0/8"}
	doScan(ips, "80,443")
}
```