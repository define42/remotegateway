package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestConverToInternServer(t *testing.T) {
	t.Run("missing-auth-user", func(t *testing.T) {
		got, err := converToInternServer(context.Background(), "alice-vm")
		if err == nil {
			t.Fatalf("expected error for missing user")
		}
		if got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
		if !strings.Contains(err.Error(), "missing auth user") {
			t.Fatalf("expected missing auth user error, got %v", err)
		}
	})

	t.Run("empty-host", func(t *testing.T) {
		ctx := withAuthUser(context.Background(), "alice")
		got, err := converToInternServer(ctx, "")
		if err == nil {
			t.Fatalf("expected error for empty host")
		}
		if got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
		if !strings.Contains(err.Error(), "empty host or user") {
			t.Fatalf("expected empty host or user error, got %v", err)
		}
	})

	t.Run("prefix-allows", func(t *testing.T) {
		ctx := withAuthUser(context.Background(), "alice")
		prev := getIPOfVm
		called := ""
		getIPOfVm = func(vmName string) (string, error) {
			called = vmName
			return "10.0.0.5", nil
		}
		t.Cleanup(func() { getIPOfVm = prev })

		got, err := converToInternServer(ctx, "alice-vm")
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if got != "10.0.0.5" {
			t.Fatalf("expected ip %q, got %q", "10.0.0.5", got)
		}
		if called != "alice-vm" {
			t.Fatalf("expected vm lookup for %q, got %q", "alice-vm", called)
		}
	})

	t.Run("prefix-propagates-error", func(t *testing.T) {
		ctx := withAuthUser(context.Background(), "alice")
		prev := getIPOfVm
		stubErr := errors.New("boom")
		getIPOfVm = func(vmName string) (string, error) {
			return "", stubErr
		}
		t.Cleanup(func() { getIPOfVm = prev })

		got, err := converToInternServer(ctx, "alice-vm")
		if got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
		if !errors.Is(err, stubErr) {
			t.Fatalf("expected %v, got %v", stubErr, err)
		}
	})

	t.Run("denies-non-prefix", func(t *testing.T) {
		ctx := withAuthUser(context.Background(), "alice")
		got, err := converToInternServer(ctx, "bob-vm")
		if err == nil {
			t.Fatalf("expected deny error")
		}
		if got != "" {
			t.Fatalf("expected empty result, got %q", got)
		}
		if !strings.Contains(err.Error(), "denying server") {
			t.Fatalf("expected deny error, got %v", err)
		}
	})
}
