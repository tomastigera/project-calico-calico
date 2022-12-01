// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// AttachedProgInfo describes what we store about an attached program.
type AttachedProgInfo struct {
	Object string `json:"object"`
	Hash   string `json:"hash"`
	ID     int    `json:"id"`
	Config string `json:"config"`
}

// AttachPointInfo describes what we need to know about an attach point
type AttachPointInfo interface {
	IfaceName() string
	HookName() Hook
	Config() string
}

// AlreadyAttachedProg checks that the program we are going to attach has the
// same parameters as what we remembered about the currently attached.
func AlreadyAttachedProg(a AttachPointInfo, object string, id int) (bool, error) {
	bytesToRead, err := ioutil.ReadFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()))
	if err != nil {
		// If file does not exist, just ignore the err code, and return false
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var progInfo AttachedProgInfo
	if err = json.Unmarshal(bytesToRead, &progInfo); err != nil {
		return false, err
	}

	hash, err := sha256OfFile(object)
	if err != nil {
		return false, err
	}

	if log.GetLevel() >= log.DebugLevel {
		log.WithFields(log.Fields{
			"iface":  a.IfaceName(),
			"hook":   a.HookName(),
			"hash":   progInfo.Hash == hash,
			"object": progInfo.Object == object,
			"id":     progInfo.ID == id,
			"config": progInfo.Config == a.Config(),
		}).Debugf("AlreadyAttachedProg result %t", progInfo.Hash == hash &&
			progInfo.Object == object && progInfo.ID == id &&
			progInfo.Config == a.Config())
	}

	return progInfo.Hash == hash &&
			progInfo.Object == object &&
			progInfo.ID == id &&
			progInfo.Config == a.Config(),
		nil
}

// RememberAttachedProg stores the attached programs parameters in a file.
func RememberAttachedProg(a AttachPointInfo, object string, id int) error {
	hash, err := sha256OfFile(object)
	if err != nil {
		return err
	}

	var progInfo = AttachedProgInfo{
		Object: object,
		Hash:   hash,
		ID:     id,
		Config: a.Config(),
	}

	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		return err
	}

	bytesToWrite, err := json.Marshal(progInfo)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(RuntimeJSONFilename(a.IfaceName(), a.HookName()), bytesToWrite, 0600); err != nil {
		return err
	}

	return nil
}

// ForgetAttachedProg removes what we store about the iface/hook
// program.
func ForgetAttachedProg(iface string, hook Hook) error {
	err := os.Remove(RuntimeJSONFilename(iface, hook))
	// If the hash file does not exist, just ignore the err code, and return false
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ForgetIfaceAttachedProg removes information we store about any programs
// associated with an iface.
func ForgetIfaceAttachedProg(iface string) error {
	for _, hook := range Hooks {
		err := ForgetAttachedProg(iface, hook)
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanAttachedProgDir makes sure /var/run/calico/bpf/prog exists and removes
// json files related to interfaces that do not exist.
func CleanAttachedProgDir() {
	if err := os.MkdirAll(RuntimeProgDir, 0600); err != nil {
		log.Errorf("Failed to create BPF hash directory. err=%v", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("Failed to get list of interfaces. err=%v", err)
	}

	expectedJSONFiles := set.New[string]()
	for _, iface := range interfaces {
		for _, hook := range Hooks {
			expectedJSONFiles.Add(RuntimeJSONFilename(iface.Name, hook))
		}
	}

	err = filepath.Walk(RuntimeProgDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == RuntimeProgDir {
			return nil
		}
		if !expectedJSONFiles.Contains(p) {
			err := os.Remove(p)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}

		return nil
	})

	if err != nil {
		log.Debugf("Error in cleaning up %s. err=%v", RuntimeProgDir, err)
	}
}

// RuntimeJSONFilename returns filename where we store information about
// attached program. The filename is [iface name]_[hook].json, for
// example, eth0_egress.json
func RuntimeJSONFilename(iface string, hook Hook) string {
	return path.Join(RuntimeProgDir, fmt.Sprintf("%s_%s.json", iface, hook))
}

func sha256OfFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", fmt.Errorf("failed to open BPF object to calculate its hash: %w", err)
	}
	hasher := sha256.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", fmt.Errorf("failed to read BPF object to calculate its hash: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// EPAttachInfo tells what programs are attached to an endpoint.
type EPAttachInfo struct {
	TCEgressId  int
	TCIngressId int
	XDPId       int
	XDPMode     string
}

// ListCalicoAttached list all programs that are attached to TC or XDP and are
// related to Calico. That is, they have jumpmap pinned in our dir hierarchy.
func ListCalicoAttached() (map[string]EPAttachInfo, error) {
	aTC, aXDP, err := ListTcXDPAttachedProgs()
	if err != nil {
		return nil, err
	}

	attachedProgIDs := set.New[int]()

	for _, p := range aXDP {
		attachedProgIDs.Add(p.ID)
	}

	maps, err := ListPerEPMaps()
	if err != nil {
		return nil, err
	}

	allProgs, err := GetAllProgs()
	if err != nil {
		return nil, err
	}

	caliProgsXdp := set.New[int]()

	for _, p := range allProgs {
		if !attachedProgIDs.Contains(p.Id) {
			continue
		}

		for _, m := range p.MapIds {
			if _, ok := maps[m]; ok {
				caliProgsXdp.Add(p.Id)
				break
			}
		}
	}

	ai := make(map[string]EPAttachInfo)

	for _, p := range aTC {
		if !strings.HasPrefix(p.Name, "calico") {
			continue
		}

		info, ok := ai[p.DevName]
		if !ok {
			info = EPAttachInfo{TCEgressId: -1, TCIngressId: -1, XDPId: -1}
		}

		switch p.Kind {
		case "clsact/ingress":
			info.TCIngressId = p.ID
			ai[p.DevName] = info
		case "clsact/egress":
			info.TCEgressId = p.ID
			ai[p.DevName] = info
		}
	}

	for _, p := range aXDP {
		if caliProgsXdp.Contains(p.ID) {
			info, ok := ai[p.DevName]
			if !ok {
				info = EPAttachInfo{TCEgressId: -1, TCIngressId: -1, XDPId: -1}
			}
			info.XDPId = p.ID
			info.XDPMode = p.Mode
			ai[p.DevName] = info
		}
	}

	return ai, nil
}

type HookDevKey struct {
	Dev  string
	Hook Hook
}

func ListHooksIDs() map[HookDevKey]int {
	// Find all the programs that are attached to interfaces.
	out, err := exec.Command("bpftool", "-j", "net").Output()
	if err != nil {
		log.WithError(err).Panic("Failed to list attached bpf programs")
	}
	log.WithField("dump", string(out)).Debug("Attached BPF programs")

	var attached []struct {
		TC []struct {
			DevName string `json:"devname"`
			ID      int    `json:"id"`
			Kind    string `json:"kind"`
			Name    string `json:"name"`
		} `json:"tc"`
		XDP []struct {
			DevName string `json:"devname"`
			IfIndex int    `json:"ifindex"`
			Mode    string `json:"mode"`
			ID      int    `json:"id"`
		} `json:"xdp"`
	}
	err = json.Unmarshal(out, &attached)
	if err != nil {
		log.WithError(err).WithField("dump", string(out)).Error("Failed to parse list of attached BPF programs")
	}

	list := make(map[HookDevKey]int)

	for _, prog := range attached[0].TC {
		if !strings.HasPrefix(prog.Name, "calico") {
			continue
		}

		k := HookDevKey{Dev: prog.DevName}
		switch prog.Kind {
		case "clsact/ingress":
			k.Hook = HookIngress
		case "clsact/egress":
			k.Hook = HookEgress
		}

		list[k] = prog.ID
	}

	for _, prog := range attached[0].XDP {
		list[HookDevKey{Dev: prog.DevName, Hook: HookXDP}] = prog.ID
	}

	return list
}
