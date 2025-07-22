// Copyright (c) 2019 Tigera Inc. All rights reserved.
package main

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

func TestEksInitBin(t *testing.T) {
	g := NewWithT(t)

	testDir := "/tmp/"
	testFile := "test-state"
	testStateTokens := map[string]string{
		testFile: "test-token",
	}

	err := generateStateFile(testDir, testStateTokens)
	g.Expect(err).ShouldNot(HaveOccurred())
	g.Expect(fileExists(testDir + testFile)).Should(BeTrue())
	g.Expect(matchesToken(testDir + testFile)).Should(Equal("test-token"))
	g.Expect(matchesToken(testDir + testFile)).Should(Not(Equal("fake-token")))
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func matchesToken(filePath string) string {
	token, err := os.ReadFile(filePath)
	if err == nil {
		return string(token)
	}

	return ""
}
