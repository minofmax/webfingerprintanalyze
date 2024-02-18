package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
)

type BaseRule struct {
	Rule       string `json:"rule"`
	RuleRegexp *regexp.Regexp
}

type ComponentsRule struct {
	Method string     `json:"method"`
	Rules  []BaseRule `json:"rules"`
}

func LoadRules() (map[string]map[string]ComponentsRule, error) {
	// 从 rules.json里把rule加载进内存
	var rules = make(map[string]map[string]ComponentsRule)
	f, err := os.OpenFile("rules.json", os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, err
	}
	file, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(file, &rules)
	if err != nil {
		return nil, err
	}
	// 提前预编译正则表达式
	for _, componentsRules := range rules {
		for _, subRules := range componentsRules {
			for i := range subRules.Rules {
				ruleRegexp, err := regexp.Compile(subRules.Rules[i].Rule)
				if err != nil {
					log.Printf("load rule: %s failed", subRules.Rules[i].Rule)
					continue
				}
				subRules.Rules[i].RuleRegexp = ruleRegexp
			}
		}
	}
	return rules, nil
}
