package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/magefile/mage/mg"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
// var Default = Build

// Build step that requires additional params, or platform specific steps for example
func Build() error {
	mg.Deps(InstallDeps)
	fmt.Println("Building...")
	cmd := exec.Command("go", "build", "-o", "MyApp", ".")
	return cmd.Run()
}

// Install step if you need your bin someplace other than go/bin
func Install() error {
	mg.Deps(Build)
	fmt.Println("Installing...")
	return os.Rename("./MyApp", "/usr/bin/MyApp")
}

// InstallDeps manage your deps, or running package managers.
func InstallDeps() error {
	fmt.Println("Installing Deps...")
	return nil
}

// Clean up after yourself
func Clean() error {
	fmt.Println("Cleaning...")
	return os.RemoveAll("MyApp")
}
