package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// profilesCreate posts a profile-creation payload and returns the recorder.
func profilesCreate(t *testing.T, mux *http.ServeMux, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/profiles", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestProfilesCreateValidation pins the server-side input validation added
// in round 12: the endpoint used to store anything verbatim (empty names,
// negative beacon intervals, jitter > 1, unknown transports) as permanent
// rows the console would render. Defaults survive (0 interval -> 5s,
// 0 jitter -> 0.3, empty transport -> tls); nonsense is a 400.
func TestProfilesCreateValidation(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	t.Run("valid payload creates with defaults", func(t *testing.T) {
		rec := profilesCreate(t, mux, token, `{"name":"corp-beacon"}`)
		if rec.Code != 200 {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name string
			body string
		}{
			{"empty name", `{"name":""}`},
			{"whitespace name", `{"name":"   "}`},
			{"name over 64 chars", `{"name":"` + strings.Repeat("x", 65) + `"}`},
			{"negative interval", `{"name":"a","beacon_interval":-5}`},
			{"interval over an hour", `{"name":"a","beacon_interval":3601}`},
			{"negative jitter", `{"name":"a","jitter":-0.1}`},
			{"jitter over 0.95", `{"name":"a","jitter":1.5}`},
			{"unknown transport", `{"name":"a","transport":"carrier-pigeon"}`},
		}
		for _, tc := range cases {
			rec := profilesCreate(t, mux, token, tc.body)
			if rec.Code != 400 {
				t.Errorf("%s: got %d, want 400 (body: %s)", tc.name, rec.Code, rec.Body.String())
			}
		}
	})
}

// TestProfilesLifecycle covers the full console flow: create -> list shows
// the row -> delete -> 200 -> gone from the listing -> deleting the same id
// again is an honest 404 (not a silent no-op).
func TestProfilesLifecycle(t *testing.T) {
	mux, _ := buildAuthTestStack(t)
	token := login(t, mux)

	rec := profilesCreate(t, mux, token, `{"name":"lifecycle","beacon_interval":15,"jitter":0.2,"transport":"dns"}`)
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	list := authedGet(t, mux, "/api/profiles", token)
	if list.Code != 200 {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	// The listing must contain exactly our row (fresh test DB).
	if !strings.Contains(list.Body.String(), `"name":"lifecycle"`) ||
		!strings.Contains(list.Body.String(), `"transport":"dns"`) {
		t.Fatalf("created profile missing from listing: %s", list.Body.String())
	}

	// Extract the id the API minted (list after the second create).
	if rec2 := profilesCreate(t, mux, token, `{"name":"lifecycle2"}`); rec2.Code != 200 {
		t.Fatalf("second create: %d", rec2.Code)
	}
	req := httptest.NewRequest("GET", "/api/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, req)
	if listRec.Code != 200 {
		t.Fatalf("second list: %d", listRec.Code)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(listRec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	createdID := ""
	for _, row := range rows {
		if row["name"] == "lifecycle2" {
			createdID, _ = row["id"].(string)
		}
	}
	if createdID == "" {
		t.Fatal("lifecycle2 profile not found in listing")
	}

	// DELETE it: 200 with status deleted.
	del := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("DELETE", "/api/profiles/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		return r
	}
	if d := del(createdID); d.Code != 200 {
		t.Fatalf("delete: %d %s", d.Code, d.Body.String())
	}

	// Second DELETE of the same id: 404 profile not found.
	if d := del(createdID); d.Code != 404 {
		t.Fatalf("re-delete: %d, want 404", d.Code)
	}

	// Path hygiene: an id with a control character is a 400, not a lookup.
	if d := del("profile%00x"); d.Code != 400 {
		t.Fatalf("control-char id: %d, want 400", d.Code)
	}
}
