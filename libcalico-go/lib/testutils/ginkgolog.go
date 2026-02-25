// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func HookLogrusForGinkgo() {
	// Set up logging formatting.
	formatter := logutils.ConfigureFormatter("test")
	logrus.SetOutput(ginkgo.GinkgoWriter)
	// We don't want logrus.Fatal to call os.Exit (which would exit the
	// test with no output).  Convert to a panic.
	logrus.AddHook(&PanicOnFatalHook{Formatter: formatter})
	logrus.SetLevel(logrus.DebugLevel)
}

type PanicOnFatalHook struct {
	Formatter *logutils.Formatter
}

func (p PanicOnFatalHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.FatalLevel,
	}
}

func (p PanicOnFatalHook) Fire(entry *logrus.Entry) error {
	f, err := p.Formatter.Format(entry)
	if err != nil {
		panic(spew.Sprint("Failed to format logrus entry", err, entry))
	}
	panic(fmt.Sprintf("logrus.Fatal called: %s", f))
}
