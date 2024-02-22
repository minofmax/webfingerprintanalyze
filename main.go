package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

func portScan(ipList []string, portRange string) []PortResult {
	scanResult, err := DoNabbuScan(ipList, portRange, nil)
	if err != nil {
		log.Fatal("执行端口扫描失败")
		return nil
	}
	return scanResult
}

func identifyFingerprint(openedPorts []string, goRoutinePoolSize int) []string {
	var identifiedComponents []string

	rules, err := LoadRules()
	if err != nil {
		log.Println(err)
		return identifiedComponents
	}

	for path, componentsRules := range rules {
		func(path string, componentsRules map[string]ComponentsRule) {
			for component, subRules := range componentsRules {
				method := subRules.Method
				matchedRules := subRules.Rules
				wg := sync.WaitGroup{}
				ch := make(chan struct{}, goRoutinePoolSize)
				for _, openedPort := range openedPorts {
					ch <- struct{}{}
					wg.Add(1)
					go func(method string, openedPort string, path string, component string, matchedRules []BaseRule) {
						defer wg.Done()

						httpPacket := DoHttpRequest(method, openedPort, path, "")
						httpResponse := httpPacket.HttpResponse
						httpsResponse := httpPacket.HttpsResponse
						for _, rule := range matchedRules {
							log.Printf("component: %s, openedport: %s, path: %s", component, openedPort, path)
							ruleRegexp := rule.RuleRegexp
							httpResponseMatchStatus := false
							httpsResponseMatchStatus := false
							if ruleRegexp.Match(httpResponse) {
								log.Printf("opened ports: %s, fingerprint is [%s], matched rule [%s], uri is %s",
									openedPort, component, rule.Rule, httpPacket.Uri)
								httpResponseMatchStatus = true
								identifiedComponents = append(identifiedComponents, fmt.Sprintf("url: %s, component: %s", "http://"+openedPort+path, component))
							}
							if rule.RuleRegexp.Match(httpsResponse) {
								log.Printf("opened ports: %s, fingerprint is [%s], matched rule [%s], uri is %s",
									openedPort, component, rule.Rule, httpPacket.Uri)
								httpsResponseMatchStatus = true
								identifiedComponents = append(identifiedComponents, fmt.Sprintf("url: %s, component: %s", "https://"+openedPort+"/"+path, component))
							}
							// 命中一条规则即退出
							if httpsResponseMatchStatus || httpResponseMatchStatus {
								return
							}
						}
						<-ch
					}(method, openedPort, path, component, matchedRules)
				}
				// 等待go routine pool执行完毕
				wg.Wait()
				close(ch)
			}
		}(path, componentsRules)
		log.Printf("path: %s match completed", path)
	}

	log.Println("扫描完毕")
	return identifiedComponents
}

func doScan(ipAddresses []string, portRange string) {
	openedPort := portScan(ipAddresses, portRange)
	var openedPorts []string
	for _, p := range openedPort {
		ipAddress := p.IpAddress
		port := p.PortId
		openedPorts = append(openedPorts, fmt.Sprintf("%s:%d", ipAddress, port))
	}
	openedPorts = CheckIsWebPort(openedPorts, 10, 5)
	fingerprints := identifyFingerprint(openedPorts, 3)
	fmt.Println(strings.Repeat("*", 30)+" Results "+strings.Repeat("*", 30), "\n", "[Opened Ports]", openedPort, "\n", "[Fingerprints]", fingerprints)
}
