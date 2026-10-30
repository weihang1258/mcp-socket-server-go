package main

import (
	"io"
	"os"
	"testing"
)

// captureInstallOutput 捕获 fn 执行期间的 stdout+stderr（installSelf 直接打印）。
func captureInstallOutput(t *testing.T, fn func()) string {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	fn()
	w.Close()
	return <-done
}
