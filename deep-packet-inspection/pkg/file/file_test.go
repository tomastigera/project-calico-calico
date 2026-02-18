// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package file_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/file"
)

var _ = Describe("File", func() {
	path := "pkg/file/test"
	BeforeEach(func() {
		_ = os.RemoveAll(path)
		_ = os.MkdirAll(path, os.ModePerm)
	})

	AfterEach(func() {
		err := os.RemoveAll(path)
		Expect(err).ShouldNot(HaveOccurred())
	})
	It("Should delete older files on interval", func() {
		for i := 0; i < 10; i++ {
			_, err := os.Create(fmt.Sprintf("%s/alert_fast.txt.180000000%d", path, i))
			Expect(err).ShouldNot(HaveOccurred())
		}
		_, err := os.Create(fmt.Sprintf("%s/alert_fast.txt", path))
		Expect(err).ShouldNot(HaveOccurred())

		ctx, cancelFn := context.WithCancel(context.Background())
		f := file.NewFileMaintainer(1 * time.Second)
		f.Run(ctx)
		f.Maintain(path)

		By("verifying older files are deleted")
		for i := 4; i < 10; i++ {
			Eventually(func() error {
				_, err := os.Stat(fmt.Sprintf("%s/alert_fast.txt.180000000%d", path, i))
				return err
			}, 10*time.Second).Should(HaveOccurred())
		}

		_, err = os.Stat(fmt.Sprintf("%s/alert_fast.txt.1800000004", path))
		Expect(os.IsNotExist(err)).Should(BeTrue())

		By("verifying that maximum allowed files are not deleted")
		for i := 0; i < 4; i++ {
			_, err := os.Stat(fmt.Sprintf("%s/alert_fast.txt.180000000%d", path, i))
			Expect(err).ShouldNot(HaveOccurred())
		}

		f.Stop(path)
		cancelFn()
	})
})
