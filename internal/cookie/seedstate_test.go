package cookie

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSeedState(t *testing.T) {
	browser := makeBrowser(t, t.TempDir(), "Default")
	profile := "Default"
	dbPath := browser.CookiesDB(profile)
	initDB(t, dbPath, v24SQL)
	key := testKey(t)

	now := float64(time.Now().Unix())
	live := unixSecondsToChromeMicros(now + 86_400)
	expired := unixSecondsToChromeMicros(now - 86_400)
	insertRaw(t, dbPath, ".alpha.example", "alpha", "/", mustEncrypt(t, "one", key, ".alpha.example"), live)
	insertRaw(t, dbPath, ".beta.example", "beta", "/two", mustEncrypt(t, "two", key, ".beta.example"), live)
	insertRaw(t, dbPath, ".alpha.example", "session", "/", mustEncrypt(t, "three", key, ".alpha.example"), 0)
	insertRaw(t, dbPath, ".alpha.example", "garbage", "/", []byte{0xff}, live)
	insertRaw(t, dbPath, ".beta.example", "expired", "/", mustEncrypt(t, "stale", key, ".beta.example"), expired)

	if err := os.MkdirAll(browser.LocalStorageDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir local storage: %v", err)
	}
	writeLevelDB(t, browser.LocalStorageDir(profile), map[string][]byte{
		string(lsKey("https://alpha.example", "local-alpha")): latin1Val("one"),
		string(lsKey("https://beta.example", "local-beta")):   latin1Val("two"),
	})
	if err := os.MkdirAll(browser.SessionStorageDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir session storage: %v", err)
	}
	writeLevelDB(t, browser.SessionStorageDir(profile), map[string][]byte{
		"namespace-aaaa_1111-https://alpha.example/": []byte("7"),
		"namespace-bbbb_2222-https://beta.example/":  []byte("9"),
		"map-7-session-alpha":                        utf16LEBytes("three"),
		"map-9-session-beta":                         utf16LEBytes("four"),
	})

	state, skipped, err := SeedState(context.Background(), browser, profile, key)
	if err != nil {
		t.Fatalf("SeedState: %v", err)
	}

	want := StorageState{
		Cookies: []Cookie{
			{
				HostKey:       ".alpha.example",
				Name:          "alpha",
				Value:         "one",
				Path:          "/",
				ExpiresUTC:    live,
				LastUpdateUTC: sampleUpdate,
				CreationUTC:   sampleCreation,
				IsSecure:      true,
				SourceScheme:  2,
				SourcePort:    443,
			},
			{
				HostKey:       ".beta.example",
				Name:          "beta",
				Value:         "two",
				Path:          "/two",
				ExpiresUTC:    live,
				LastUpdateUTC: sampleUpdate,
				CreationUTC:   sampleCreation,
				IsSecure:      true,
				SourceScheme:  2,
				SourcePort:    443,
			},
			{
				HostKey:       ".alpha.example",
				Name:          "session",
				Value:         "three",
				Path:          "/",
				LastUpdateUTC: sampleUpdate,
				CreationUTC:   sampleCreation,
				IsSecure:      true,
				SourceScheme:  2,
				SourcePort:    443,
			},
		},
		Origins: []OriginStorage{
			{
				Origin:         "https://alpha.example",
				LocalStorage:   []WebStorageEntry{{Name: "local-alpha", Value: "one"}},
				SessionStorage: []WebStorageEntry{{Name: "session-alpha", Value: "three"}},
			},
			{
				Origin:         "https://beta.example",
				LocalStorage:   []WebStorageEntry{{Name: "local-beta", Value: "two"}},
				SessionStorage: []WebStorageEntry{{Name: "session-beta", Value: "four"}},
			},
		},
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("SeedState = %#v, want %#v", state, want)
	}
}
