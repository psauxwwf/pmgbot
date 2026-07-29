package pmgbot

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScanDeletedSpamPaths(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`ignored /var/spool/pmg/cluster/1/spam/AA/BBBB`,
		`marked as deleted: /var/spool/pmg/cluster/2/spam/ab/cdef`,
		`marked as deleted: /var/spool/pmg/cluster/2/spam/ab/cdef`,
	}, "\n"))

	paths, err := scanDeletedSpamPaths(input)
	if err != nil {
		t.Fatal(err)
	}

	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1: %#v", len(paths), paths)
	}
	if !slices.Contains(paths, `/var/spool/pmg/cluster/2/spam/ab/cdef`) {
		t.Fatalf("missing expected spam path: %#v", paths)
	}
}

func TestSinceFromBefore(t *testing.T) {
	now := time.Date(2026, 7, 29, 15, 55, 0, 0, time.UTC)

	got := sinceFromBefore(now, 30*time.Minute)
	want := "2026-07-29 15:25:00"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFirstEmail(t *testing.T) {
	got := firstEmail(`From: Name <USER.Name+tag@Example.COM>`)
	want := `USER.Name+tag@Example.COM`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSenderFromFileFallsBackToFrom(t *testing.T) {
	path := filepath.Join(t.TempDir(), "message.eml")
	content := strings.Join([]string{
		`Return-Path: <>`,
		`Return-Path: <ignored@example.com>`,
		`From: Sender <sender@example.com>`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := senderFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `sender@example.com`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExistingBlacklistSenders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.txt")
	content := strings.Join([]string{
		` old@example.com `,
		`OLD@example.com`,
		``,
		`next@example.com`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := existingBlacklistSenders(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`old@example.com`, `next@example.com`}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestAppendUniqueSenders(t *testing.T) {
	got := appendUniqueSenders(
		[]string{`old@example.com`, `keep@example.com`},
		[]string{`new@example.com`, `OLD@example.com`, ` new@example.com `},
	)
	want := []string{`old@example.com`, `keep@example.com`, `new@example.com`}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
