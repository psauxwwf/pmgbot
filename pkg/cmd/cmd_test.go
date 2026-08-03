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

	regular, cancel, err := New("true", []string{"--help"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if filepath.Base(regular.cmd.Path) != "true" {
		t.Fatalf("got path %q, want binary %q", regular.cmd.Path, "true")
	}
	wantRegularArgs := []string{"true", "--help"}
	if !reflect.DeepEqual(regular.cmd.Args, wantRegularArgs) {
		t.Fatalf("got args %v, want %v", regular.cmd.Args, wantRegularArgs)
	}

	SetSudo(true)
	withSudo, cancel, err := New("true", []string{"--help"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if filepath.Base(withSudo.cmd.Path) != "sudo" {
		t.Fatalf("got path %q, want binary %q", withSudo.cmd.Path, "sudo")
	}
	wantSudoArgs := []string{"sudo", "true", "--help"}
	if !reflect.DeepEqual(withSudo.cmd.Args, wantSudoArgs) {
		t.Fatalf("got args %v, want %v", withSudo.cmd.Args, wantSudoArgs)
	}
}
