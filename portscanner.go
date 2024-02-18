package main

import (
	"github.com/minofmax/naabu/v2/pkg/result"
	"github.com/minofmax/naabu/v2/pkg/runner"
	"log"
)

type PortResult struct {
	IpAddress string `json:"ipAddress"`
	PortId    int    `json:"portId"`
	Service   string `json:"service"`
	Product   string `json:"product"`
}

func nmapResultHandler(xml []byte) []PortResult {
	var results []PortResult
	parse, err := Parse(xml)
	if err != nil {
		return results
	}
	hosts := parse.Hosts

	for _, value := range hosts {
		ipAddresses := value.Addresses
		ports := value.Ports
		for _, port := range ports {
			portId := port.PortId
			service := port.Service.Name
			product := port.Service.Product
			state := port.State.State
			if state == "open" {
				results = append(results, PortResult{
					IpAddress: ipAddresses[0].Addr,
					PortId:    portId,
					Service:   service,
					Product:   product,
				})
			}
		}
	}
	return results
}

func DoNabbuScan(ipAddresses []string, portRange string, options *runner.Options) ([]PortResult, error) {
	// 只识别开放端口，不做指纹识别
	var openedPorts []PortResult
	if options == nil {
		options = &runner.Options{
			Host:     ipAddresses,
			ScanType: "s",
			Silent:   true,
			OnResult: func(hr *result.HostResult) {
				for _, port := range hr.Ports {
					openedPorts = append(openedPorts, PortResult{
						IpAddress: hr.IP,
						PortId:    port.Port,
					})
				}
			},
			Ports: portRange,
		}
	}

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return openedPorts, err
	}
	defer naabuRunner.Close()

	err, _ = naabuRunner.RunEnumeration()
	if err != nil {
		return openedPorts, err
	}
	log.Printf("端口扫描结束, 发现开放端口数: %d", len(openedPorts))
	return openedPorts, nil
}

func DoNmapScan(ipAddresses []string, portRange string, options *runner.Options) ([]PortResult, error) {
	// 执行扫描，用户自定义ip/ip段和目标端口段进行扫描，支持自定义naabu的options，同时在选择nmap扫描的时候，
	// 会将nmap的扫描结果作为最终结果返回, 借助了nmap的基础指纹识别能力
	if options == nil {
		options = &runner.Options{
			Host:             ipAddresses,
			Nmap:             true,
			NmapCLI:          "nmap -sV -oX - -Pn",
			ServiceDiscovery: true,
			ServiceVersion:   true,
			ScanType:         "s",
			Rate:             3000,
			Threads:          30,
			Silent:           true,
			//OnResult: func(hr *result.HostResult) {
			//	fmt.Println(hr.Ports)
			//},
			Ports: portRange,
		}
	}

	var results []PortResult
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return results, err
	}
	defer naabuRunner.Close()

	err, nmapOutput := naabuRunner.RunEnumeration()
	if err != nil {
		return results, err
	}
	results = nmapResultHandler(nmapOutput)
	log.Printf("端口扫描结束, 发现开放端口数: %d", len(results))
	return results, nil
}
