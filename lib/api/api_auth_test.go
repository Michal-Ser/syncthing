// Copyright (C) 2014 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syncthing/syncthing/internal/db"
	"github.com/syncthing/syncthing/internal/db/sqlite"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/events"
)

var guiCfg config.GUIConfiguration

func init() {
	guiCfg.User = "user"
	guiCfg.SetPassword("pass")
}

func TestStaticAuthOK(t *testing.T) {
	t.Parallel()

	ok := authStatic("user", "pass", guiCfg)
	if !ok {
		t.Fatalf("should pass auth")
	}
}

func TestSimpleAuthUsernameFail(t *testing.T) {
	t.Parallel()

	ok := authStatic("userWRONG", "pass", guiCfg)
	if ok {
		t.Fatalf("should fail auth")
	}
}

func TestStaticAuthPasswordFail(t *testing.T) {
	t.Parallel()

	ok := authStatic("user", "passWRONG", guiCfg)
	if ok {
		t.Fatalf("should fail auth")
	}
}

func TestFormatOptionalPercentS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		template string
		username string
		expected string
	}{
		{"cn=%s,dc=some,dc=example,dc=com", "username", "cn=username,dc=some,dc=example,dc=com"},
		{"cn=fixedusername,dc=some,dc=example,dc=com", "username", "cn=fixedusername,dc=some,dc=example,dc=com"},
		{"cn=%%s,dc=%s,dc=example,dc=com", "username", "cn=%s,dc=username,dc=example,dc=com"},
		{"cn=%%s,dc=%%s,dc=example,dc=com", "username", "cn=%s,dc=%s,dc=example,dc=com"},
		{"cn=%s,dc=%s,dc=example,dc=com", "username", "cn=username,dc=username,dc=example,dc=com"},
	}

	for _, c := range cases {
		templatedDn := formatOptionalPercentS(c.template, c.username)
		if c.expected != templatedDn {
			t.Fatalf("result should be %s != %s", c.expected, templatedDn)
		}
	}
}

type mockClock struct {
	now time.Time
}

func (c *mockClock) Now() time.Time {
	c.now = c.now.Add(1) // time always ticks by at least 1 ns
	return c.now
}

func (c *mockClock) wind(t time.Duration) {
	c.now = c.now.Add(t)
}

func TestTokenManager(t *testing.T) {
	t.Parallel()

	mdb, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mdb.Close()
	})
	kdb := db.NewMiscDB(mdb)
	clock := &mockClock{now: time.Now()}

	// Token manager keeps up to three tokens with a validity time of 24 hours.
	tm := newTokenManager("testTokens", kdb, 24*time.Hour, 3)
	tm.timeNow = clock.Now

	// Create three tokens
	t0 := tm.New()
	t1 := tm.New()
	t2 := tm.New()

	// Check that the tokens are valid
	if !tm.Check(t0) {
		t.Errorf("token %q should be valid", t0)
	}
	if !tm.Check(t1) {
		t.Errorf("token %q should be valid", t1)
	}
	if !tm.Check(t2) {
		t.Errorf("token %q should be valid", t2)
	}

	// Create a fourth token
	t3 := tm.New()
	// It should be valid
	if !tm.Check(t3) {
		t.Errorf("token %q should be valid", t3)
	}
	// But the first token should have been removed
	if tm.Check(t0) {
		t.Errorf("token %q should be invalid", t0)
	}

	// Wind the clock by 12 hours
	clock.wind(12 * time.Hour)
	// The second token should still be valid (and checking it will give it more life)
	if !tm.Check(t1) {
		t.Errorf("token %q should be valid", t1)
	}

	// Wind the clock by 12 hours
	clock.wind(12 * time.Hour)
	// The second token should still be valid
	if !tm.Check(t1) {
		t.Errorf("token %q should be valid", t1)
	}
	// But the third and fourth tokens should have expired
	if tm.Check(t2) {
		t.Errorf("token %q should be invalid", t2)
	}
	if tm.Check(t3) {
		t.Errorf("token %q should be invalid", t3)
	}
}

func TestTokenManagerNoExpiry(t *testing.T) {
	t.Parallel()

	mdb, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mdb.Close()
	})
	kdb := db.NewMiscDB(mdb)
	clock := &mockClock{now: time.Now()}

	tm := newTokenManager("testTokensNoExpiry", kdb, -1, 3)
	tm.timeNow = clock.Now

	token := tm.New()
	if expiry, ok := tm.tokens.Tokens[token]; !ok || expiry != 0 {
		t.Fatalf("token should have no expiry, got %d", expiry)
	}

	clock.wind(365 * 24 * time.Hour)
	if !tm.Check(token) {
		t.Fatal("token should still be valid after long time when no-expiry is enabled")
	}
}

func TestSessionCookieMaxAgeNoExpiry(t *testing.T) {
	t.Parallel()

	m := tokenCookieManager{
		guiCfg: config.GUIConfiguration{
			SessionCookieDurationS: -1,
		},
	}
	if got := m.sessionCookieMaxAge(); got != math.MaxInt32 {
		t.Fatalf("unexpected max age %d", got)
	}
}

func TestProxyAuth(t *testing.T) {
	t.Parallel()

	mdb, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mdb.Close()
	})
	kdb := db.NewMiscDB(mdb)

	cfg := guiCfg
	cfg.APIKey = "testapikey"
	cfg.ProxyAuthHeader = "Remote-User"
	cfg.ProxyAuthTrustedNets = "192.0.2.10/32, 2001:db8::/64, not-a-network"
	cfg.ProxyAuthAllowedUsers = "alice, bob"

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name       string
		cfg        func(c *config.GUIConfiguration)
		remoteAddr string
		headers    map[string]string
		wantStatus int
		wantCookie bool
	}{
		{"trusted proxy", nil, "192.0.2.10:1234", map[string]string{"Remote-User": "alice"}, http.StatusOK, true},
		{"trusted proxy, ipv6", nil, "[2001:db8::1]:1234", map[string]string{"Remote-User": "bob"}, http.StatusOK, true},
		{"trusted proxy, ipv4 mapped", nil, "[::ffff:192.0.2.10]:1234", map[string]string{"Remote-User": "alice"}, http.StatusOK, true},
		{"untrusted source", nil, "192.0.2.11:1234", map[string]string{"Remote-User": "alice"}, http.StatusForbidden, false},
		{"trusted proxy, no header", nil, "192.0.2.10:1234", nil, http.StatusForbidden, false},
		{"trusted proxy, user not allowed", nil, "192.0.2.10:1234", map[string]string{"Remote-User": "printer"}, http.StatusForbidden, false},
		{"any user allowed", func(c *config.GUIConfiguration) { c.ProxyAuthAllowedUsers = "" }, "192.0.2.10:1234", map[string]string{"Remote-User": "printer"}, http.StatusOK, true},
		{"disabled without header name", func(c *config.GUIConfiguration) { c.ProxyAuthHeader = "" }, "192.0.2.10:1234", map[string]string{"Remote-User": "alice"}, http.StatusForbidden, false},
		{"disabled without trusted nets", func(c *config.GUIConfiguration) { c.ProxyAuthTrustedNets = "" }, "192.0.2.10:1234", map[string]string{"Remote-User": "alice"}, http.StatusForbidden, false},
		{"api key still works", nil, "192.0.2.11:1234", map[string]string{"X-API-Key": "testapikey"}, http.StatusOK, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.cfg != nil {
				tc.cfg(&c)
			}
			tcm := newTokenCookieManager("TESTID", c, events.NoopLogger, kdb)
			mw := newBasicAuthAndSessionMiddleware(tcm, c, config.LDAPConfiguration{}, next, events.NoopLogger)

			req := httptest.NewRequest(http.MethodGet, "/rest/system/status", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if gotCookie := len(rec.Result().Cookies()) > 0; gotCookie != tc.wantCookie {
				t.Errorf("session cookie set = %v, want %v", gotCookie, tc.wantCookie)
			}
		})
	}
}
