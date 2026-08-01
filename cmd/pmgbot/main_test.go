package main

import (
	"testing"
	"time"
)

func TestRootCommandsAndFlags(t *testing.T) {
	root := rootCmd()

	parse, _, err := root.Find([]string{"parse"})
	if err != nil {
		t.Fatal(err)
	}
	if parse == nil {
		t.Fatal("parse command not found")
	}
	for _, name := range []string{"before", "timeout"} {
		if parse.Flags().Lookup(name) == nil {
			t.Fatalf("parse flag %q not found", name)
		}
	}
	if parse.Flags().Lookup("cmd-timeout") != nil {
		t.Fatal("old parse flag \"cmd-timeout\" found")
	}
	if parse.Flags().Lookup("since") != nil {
		t.Fatal("old parse flag \"since\" found")
	}
	if parse.Flags().Lookup("output") != nil {
		t.Fatal("old parse flag \"output\" found")
	}

	importer, _, err := root.Find([]string{"import"})
	if err != nil {
		t.Fatal(err)
	}
	if importer == nil {
		t.Fatal("import command not found")
	}
	for _, name := range []string{"name", "timeout"} {
		if importer.Flags().Lookup(name) == nil {
			t.Fatalf("import flag %q not found", name)
		}
	}
	if importer.Flags().Lookup("cmd-timeout") != nil {
		t.Fatal("old import flag \"cmd-timeout\" found")
	}
	for _, name := range []string{"before", "since", "output"} {
		if importer.Flags().Lookup(name) != nil {
			t.Fatalf("parse-only flag %q found on import command", name)
		}
	}

	for _, name := range []string{"blacklist", "exclude", "log-level", "log-path", "sudo"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Fatalf("common flag %q not found", name)
		}
	}

	daemon, _, err := root.Find([]string{"daemon"})
	if err != nil {
		t.Fatal(err)
	}
	if daemon == nil {
		t.Fatal("daemon command not found")
	}
	for _, name := range []string{"before", "since", "timeout", "cmd-timeout", "name"} {
		if daemon.Flags().Lookup(name) != nil {
			t.Fatalf("yaml-only daemon flag %q found", name)
		}
	}

	for _, name := range []string{"config", "save-config"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Fatalf("config flag %q not found", name)
		}
	}
}

func TestParseBeforeDefault(t *testing.T) {
	root := rootCmd()
	parse, _, err := root.Find([]string{"parse"})
	if err != nil {
		t.Fatal(err)
	}

	flag := parse.Flags().Lookup("before")
	if flag == nil {
		t.Fatal("parse flag \"before\" not found")
	}
	if flag.DefValue != defaultBefore.String() {
		t.Fatalf("got %q, want %q", flag.DefValue, defaultBefore.String())
	}
}

func TestBlacklistDefault(t *testing.T) {
	root := rootCmd()

	flag := root.PersistentFlags().Lookup("blacklist")
	if flag == nil {
		t.Fatal("common flag \"blacklist\" not found")
	}
	if flag.DefValue != "blacklist.txt" {
		t.Fatalf("got %q, want %q", flag.DefValue, "blacklist.txt")
	}
}

func TestExcludeDefault(t *testing.T) {
	root := rootCmd()

	flag := root.PersistentFlags().Lookup("exclude")
	if flag == nil {
		t.Fatal("common flag \"exclude\" not found")
	}
	if flag.DefValue != defaultExclude {
		t.Fatalf("got %q, want %q", flag.DefValue, defaultExclude)
	}
}

func TestImportTimeoutDefault(t *testing.T) {
	root := rootCmd()
	importer, _, err := root.Find([]string{"import"})
	if err != nil {
		t.Fatal(err)
	}

	flag := importer.Flags().Lookup("timeout")
	if flag == nil {
		t.Fatal("import flag \"timeout\" not found")
	}
	if flag.DefValue != defaultImportTimeout.String() {
		t.Fatalf("got %q, want %q", flag.DefValue, defaultImportTimeout.String())
	}
}

func TestSudoDefault(t *testing.T) {
	root := rootCmd()

	flag := root.PersistentFlags().Lookup("sudo")
	if flag == nil {
		t.Fatal("common flag \"sudo\" not found")
	}
	if flag.DefValue != "true" {
		t.Fatalf("got %q, want %q", flag.DefValue, "true")
	}
}

func TestImportNameDefault(t *testing.T) {
	root := rootCmd()
	importer, _, err := root.Find([]string{"import"})
	if err != nil {
		t.Fatal(err)
	}

	flag := importer.Flags().Lookup("name")
	if flag == nil {
		t.Fatal("import flag \"name\" not found")
	}
	if flag.DefValue != defaultImporterWhoName {
		t.Fatalf("got %q, want %q", flag.DefValue, defaultImporterWhoName)
	}
}

func TestConfigDefault(t *testing.T) {
	config := defaultFileConfig(time.Date(2026, 7, 29, 15, 55, 0, 0, time.UTC))

	if config.LogLevel != defaultLogLevel {
		t.Fatalf("got log level %q, want %q", config.LogLevel, defaultLogLevel)
	}
	if !config.Sudo {
		t.Fatal("default config sudo must be enabled")
	}
	if config.Exclude != defaultExclude {
		t.Fatalf("got exclude %q, want %q", config.Exclude, defaultExclude)
	}
	if time.Duration(config.Daemon.Before) != defaultBefore {
		t.Fatalf("got daemon before %s, want %s", time.Duration(config.Daemon.Before), defaultBefore)
	}
	if time.Duration(config.Daemon.Every) != defaultDaemonEvery {
		t.Fatalf("got daemon every %s, want %s", time.Duration(config.Daemon.Every), defaultDaemonEvery)
	}
	if time.Duration(config.Daemon.ParseTimeout) != defaultParseTimeout {
		t.Fatalf("got daemon parse timeout %s, want %s", time.Duration(config.Daemon.ParseTimeout), defaultParseTimeout)
	}
	if time.Duration(config.Daemon.ImportTimeout) != defaultImportTimeout {
		t.Fatalf("got daemon import timeout %s, want %s", time.Duration(config.Daemon.ImportTimeout), defaultImportTimeout)
	}
	if config.Daemon.ImporterWhoName != defaultImporterWhoName {
		t.Fatalf("got daemon importer who name %q, want %q", config.Daemon.ImporterWhoName, defaultImporterWhoName)
	}
}
