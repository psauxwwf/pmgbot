package cmd

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNewUsesSudoWhenEnabled(t *testing.T) {
	SetSudo(false)
	t.Cleanup(func() { SetSudo(false) })

	regular, cancel, err := New("journalctl", []string{"-u", "pmgproxy"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if filepath.Base(regular.cmd.Path) != "journalctl" {
		t.Fatalf("got path %q, want binary %q", regular.cmd.Path, "journalctl")
	}
	wantRegularArgs := []string{"journalctl", "-u", "pmgproxy"}
	if !reflect.DeepEqual(regular.cmd.Args, wantRegularArgs) {
		t.Fatalf("got args %v, want %v", regular.cmd.Args, wantRegularArgs)
	}

	SetSudo(true)
	withSudo, cancel, err := New("journalctl", []string{"-u", "pmgproxy"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if filepath.Base(withSudo.cmd.Path) != "sudo" {
		t.Fatalf("got path %q, want binary %q", withSudo.cmd.Path, "sudo")
	}
	wantSudoArgs := []string{"sudo", "journalctl", "-u", "pmgproxy"}
	if !reflect.DeepEqual(withSudo.cmd.Args, wantSudoArgs) {
		t.Fatalf("got args %v, want %v", withSudo.cmd.Args, wantSudoArgs)
	}
}
