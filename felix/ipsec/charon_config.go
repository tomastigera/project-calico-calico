// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package ipsec

import (
	"fmt"
	"maps"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	CharonConfigRootDir  = "/etc/strongswan.d"
	CharonMainConfigFile = "charon.conf"

	CharonFollowRedirects          = "charon.follow_redirects"
	CharonMakeBeforeBreak          = "charon.make_before_break"
	CharonConfigItemStdoutLogLevel = "charon.filelog.stdout.default"
	CharonConfigItemStderrLogLevel = "charon.filelog.stderr.default"
)

var (
	// https://wiki.strongswan.org/projects/strongswan/wiki/LoggerConfiguration
	// Map felix log levels to charon log levels.
	felixLogLevelToCharonLogLevel = map[string]string{
		"NONE":    "-1",
		"NOTICE":  "0",
		"INFO":    "1",
		"DEBUG":   "2",
		"VERBOSE": "4",
	}

	// Map boolean values to charon config "yes" or "no" options.
	yesOrNo = map[bool]string{true: "yes", false: "no"}
)

// Data structure for rendering the Charon's config format,
// which is a tree consisting of named sections and config fields.
// https://wiki.strongswan.org/projects/strongswan/wiki/StrongswanConf
// Each section has a name, followed by C-Style curly brackets defining the sections body.
// Each section body contains a set of subsections and key/value pairs
//        settings := (section|keyvalue)*
//        section  := name { settings }
//        keyvalue := key = value\n

type ConfigTree struct {
	section map[string]*ConfigTree
	kv      map[string]string
}

func NewConfigTree(items map[string]string) *ConfigTree {
	tree := &ConfigTree{}
	for k, v := range items {
		if err := tree.AddOneKV(k, v); err != nil {
			log.WithFields(log.Fields{
				"key":   k,
				"error": err,
			}).Error("Failed to add key to config tree.")
		}
	}

	return tree
}

// Add a dot notation kv pair to config tree.
func (t *ConfigTree) AddOneKV(key, value string) error {
	// Breakdown key name into section slice and the real key.
	slice := strings.Split(key, ".")
	length := len(slice)
	if length < 2 {
		// No dot in key name
		return fmt.Errorf("no dot in key for configTree. Len %d, slice %v", length, slice)
	}
	realKey := slice[length-1]
	sections := slice[:length-1]

	// Walk through configTree, create new section if necessary.
	currentSection := t
	for _, sectionName := range sections {
		nextSection, ok := currentSection.section[sectionName]
		if !ok {
			// Add or create a new section inside current section.
			// Make next section point to it.
			if currentSection.section == nil {
				currentSection.section = map[string]*ConfigTree{sectionName: &ConfigTree{}}
			} else {
				currentSection.section[sectionName] = &ConfigTree{}
			}
			nextSection = currentSection.section[sectionName]
		}
		currentSection = nextSection
	}

	// Create or add new kv onto section.
	if currentSection.kv == nil {
		currentSection.kv = map[string]string{realKey: value}
	} else {
		currentSection.kv[realKey] = value
	}
	return nil
}

// Render configTree to strongswan config file format.
// StartSection: the section name to start with.
// linePrefix: the prefix for each line to indent. Normally it is couple of spaces.
// Result of a configTree with "charon.filelog.stdout.default": "2",
//
//	                           "charon.filelog.stderr.default": "2",
//	                           "charon.filelog.stderr.time_format": "%e %b %F"
//
//	charon {
//	  filelog {
//	    stdout {
//	      default = 2
//	    }
//	    stderr {
//	      default = 2
//	      time_format = %e %b %F
//	    }
//	  }
//	}
//
// This function will render each section and config items in an ordered pattern.
// It is not mandatory but it makes UT and debug easier.
func (c *ConfigTree) Render(startSection, linePrefix string) string {
	var result strings.Builder

	if startSection != "" {
		// Add indent for all except start of the tree.
		linePrefix += "  "
	}
	for _, k := range getSortedKey(c.section) {
		v := c.section[k]
		if v != nil {
			sectionHead := fmt.Sprintf("%s%s {\n", linePrefix, k)
			sectionBody := v.Render(k, linePrefix)
			sectionEnd := fmt.Sprintf("%s}\n", linePrefix)
			result.WriteString(sectionHead + sectionBody + sectionEnd)
		}
	}

	for _, k := range getSortedKey(c.kv) {
		v := c.kv[k]
		result.WriteString(fmt.Sprintf("%s%s = %s\n", linePrefix, k, v))
	}
	return result.String()
}

func getSortedKey(m any) (keyList []string) {
	if reflect.ValueOf(m).Kind() != reflect.Map {
		return
	}

	keys := reflect.ValueOf(m).MapKeys()
	for _, key := range keys {
		keyList = append(keyList, key.Interface().(string))
	}
	sort.Strings(keyList)
	return
}

// Structure to hold current charon config.
// We use dot notation for each config item, same as strongswan config doc.
// e.g. charon.filelog.stderr.default = 2
type CharonConfig struct {
	rootDir    string
	configFile string            // main config file
	items      map[string]string // dot notation key
}

func NewCharonConfig(rootDir, configFile string) *CharonConfig {
	mainConfig := path.Join(rootDir, configFile)

	// Main config file should exists.
	if _, err := os.Stat(mainConfig); os.IsNotExist(err) {
		log.WithField("path", mainConfig).Panic("Main config file not exists for charon")
	}

	return &CharonConfig{
		rootDir:    rootDir,
		configFile: configFile,
		items:      map[string]string{},
	}
}

// Add configuration kv pairs to current charon config.
// The old value will be overwritten.
func (c *CharonConfig) AddKVs(kv map[string]string) {
	maps.Copy(c.items, kv)
}

func (c *CharonConfig) renderToString() string {
	return NewConfigTree(c.items).Render("", "")
}

// Render current charon config to main config file.
func (c *CharonConfig) RenderToFile() {
	config := path.Join(c.rootDir, c.configFile)
	panicIfErr(writeStringToFile(config, c.renderToString()))
}

func (c *CharonConfig) SetBooleanOption(key string, bValue bool) {
	c.AddKVs(map[string]string{
		key: yesOrNo[bValue],
	})
}

func (c *CharonConfig) SetLogLevel(felixLevel string) {
	charonLevel, ok := felixLogLevelToCharonLogLevel[strings.ToUpper(felixLevel)]
	if !ok {
		log.Panicf("Set charon log level with wrong felix log value <%s>", felixLevel)
	}
	c.AddKVs(map[string]string{
		CharonConfigItemStderrLogLevel: charonLevel,
		CharonConfigItemStdoutLogLevel: charonLevel,
	})
}

func writeStringToFile(path, text string) error {
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		return fmt.Errorf("failed to write file %s", path)
	}
	return nil
}
