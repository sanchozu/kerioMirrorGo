package mirror

import (
	"database/sql"
	"path/filepath"
	"testing"

	"kerio-mirror-go/config"
	"kerio-mirror-go/db"
)

func TestGetWebFilterKey_Forced(t *testing.T) {
	cfg := &config.Config{LicenseNumber: "LIC", WebFilterForcedKey: "FORCED-KEY"}
	if got := GetWebFilterKey(cfg, nil); got != "FORCED-KEY" {
		t.Errorf("GetWebFilterKey() = %q, want FORCED-KEY", got)
	}
}

func TestGetWebFilterKey_FromDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webfilter.db")
	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.AddWebfilterKey(conn, "LIC", "DB-KEY"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{LicenseNumber: "LIC"}
	if got := GetWebFilterKey(cfg, conn); got != "DB-KEY" {
		t.Errorf("GetWebFilterKey() = %q, want DB-KEY", got)
	}
}

func TestGetWebFilterKey_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webfilter_empty.db")
	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg := &config.Config{LicenseNumber: "LIC"}
	if got := GetWebFilterKey(cfg, conn); got != "" {
		t.Errorf("GetWebFilterKey() = %q, want empty", got)
	}
}
