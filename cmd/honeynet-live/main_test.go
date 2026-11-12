package main

import "testing"

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:80": true, "[::1]:80": true, "0.0.0.0:80": false, "192.168.1.5:80": false, ":80": false, "localhost:80": false, "garbage": false} {
		if got := isLoopback(addr); got != want {
			t.Errorf("%s: got %v want %v", addr, got, want)
		}
	}
}
