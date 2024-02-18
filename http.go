package main

import (
	"bytes"
	"crypto/tls"
	"github.com/projectdiscovery/httpx/runner"
	"io"
	"log"
	"net/http"
	"time"
)

type HttpPacket struct {
	Domain          string `json:"domain"`
	Uri             string `json:"uri"`
	HttpStatusCode  int    `json:"statusCode"`
	HttpsStatusCode int    `json:"httpsStatusCode"`
	HttpResponse    []byte `json:"httpResponse"`
	HttpsResponse   []byte `json:"httpsResponse"`
}

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
		//IdleConnTimeout: true,
	},
	Timeout: 5 * time.Second,
}

func DoHttpRequest(method string, target string, path string, body string) HttpPacket {
	// 使用go自带的http客户端完成http/https协议的请求，都返回主要是为了避免用户在配置http和https端口时指向不同的服务而导致的资产发现遗漏
	var httpsStatusCode int
	var httpsRespInBytes []byte
	var httpStatusCode int
	var httpRespInBytes []byte

	httpReq, err := http.NewRequest(method, "http://"+target+"/"+path, bytes.NewBuffer([]byte(body)))
	if err == nil {
		httpReq.Header.Set("Connection", "close")
		httpResp, httperr := client.Do(httpReq)

		if httperr == nil {
			httpStatusCode = httpResp.StatusCode
			httpRespInBytes, _ = io.ReadAll(httpResp.Body)
			defer httpResp.Body.Close()
		}
	}

	httpsReq, err := http.NewRequest(method, "https://"+target+"/"+path, bytes.NewBuffer([]byte(body)))
	if err == nil {
		httpsReq.Header.Set("Connection", "close")
		httpsResp, httpserr := client.Do(httpsReq)

		if httpserr == nil {
			httpsStatusCode = httpsResp.StatusCode
			httpsRespInBytes, _ = io.ReadAll(httpsResp.Body)
			defer httpsResp.Body.Close()
		}
	}
	packet := HttpPacket{
		Domain:          target,
		Uri:             path,
		HttpStatusCode:  httpStatusCode,
		HttpsStatusCode: httpsStatusCode,
		HttpResponse:    httpRespInBytes,
		HttpsResponse:   httpsRespInBytes,
	}
	return packet
}

func CheckIsWebPort(targets []string, parallelNumber int, timeout int) []string {
	// 校验是否是web端口
	var httpPorts []string
	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: targets,
		Threads:         parallelNumber,
		Timeout:         timeout,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				log.Printf("[Err] %s: %s \n", r.Input, r.Err)
				return
			}

			httpPorts = append(httpPorts, r.Host+":"+r.Port)
		},
	}

	if err := options.ValidateOptions(); err != nil {
		log.Println(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Println(err)
	}
	defer httpxRunner.Close()
	httpxRunner.RunEnumeration()
	log.Printf("web端口识别完毕，发现%d个web端口", len(httpPorts))
	return httpPorts
}
