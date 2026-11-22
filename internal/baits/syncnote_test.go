package baits

import (
	"reflect"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

func TestSyncNote(t *testing.T) {
	synced := func(config.UserInfo) string { return "this syncs" }
	plan := []Availability{
		{Spec: Spec{ID: "desk", Synced: synced}, Available: true},
		{Spec: Spec{ID: "wallet"}, Available: true},
		{Spec: Spec{ID: "gone", Synced: synced}},
		{Spec: Spec{ID: "docs", Synced: func(config.UserInfo) string { return "" }}, Available: true},
	}
	note, ids := SyncNote(plan, config.UserInfo{}, []string{"desk", "wallet", "gone", "docs"})
	if note != "this syncs" || !reflect.DeepEqual(ids, []string{"desk"}) {
		t.Fatalf("%q %v", note, ids)
	}
	if note, ids := SyncNote(plan, config.UserInfo{}, []string{"wallet"}); note != "" || ids != nil {
		t.Fatalf("nothing chosen syncs: %q %v", note, ids)
	}
}
