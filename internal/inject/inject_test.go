package inject

import (
	"net/url"
	"testing"
)

const pay = "%0d%0aX-H%3a%20v"

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Appending a payload to the end of a URL string rewrites any target that
// already carries a query: https://t/a?b=c would become
// https://t/a?b=c/<payload>, which pushes the payload inside the value of b
// and usually just produces a 404. These cases pin down that the query is
// preserved and that the payload lands exactly where the sink says.
func TestBuildPreservesURLStructure(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		point     Point
		wantPath  string
		wantQuery string
	}{
		{
			name:      "path append keeps the existing query intact",
			url:       "https://t.com/a?b=c",
			point:     Point{Kind: PathAppend},
			wantPath:  "/a" + pay,
			wantQuery: "b=c",
		},
		{
			name:      "query value is appended to, not replaced",
			url:       "https://t.com/p?next=/home&id=7",
			point:     Point{Kind: QueryValue, Param: "next", index: 0},
			wantPath:  "/p",
			wantQuery: "next=/home" + pay + "&id=7",
		},
		{
			name:      "second query value",
			url:       "https://t.com/p?next=/home&id=7",
			point:     Point{Kind: QueryValue, Param: "id", index: 1},
			wantPath:  "/p",
			wantQuery: "next=/home&id=7" + pay,
		},
		{
			name:      "query name sink",
			url:       "https://t.com/p?next=/home",
			point:     Point{Kind: QueryName, Param: "next", index: 0},
			wantPath:  "/p",
			wantQuery: "next" + pay + "=/home",
		},
		{
			name:      "new parameter added to an existing query",
			url:       "https://t.com/p?a=1",
			point:     Point{Kind: QueryNew},
			wantPath:  "/p",
			wantQuery: "a=1&clrfkd=" + pay,
		},
		{
			name:      "new parameter on a URL with no query",
			url:       "https://t.com/p",
			point:     Point{Kind: QueryNew},
			wantPath:  "/p",
			wantQuery: "clrfkd=" + pay,
		},
		{
			name:      "path slash sink does not double the separator",
			url:       "https://t.com/a/",
			point:     Point{Kind: PathSlash},
			wantPath:  "/a/" + pay,
			wantQuery: "",
		},
		{
			name:      "root path",
			url:       "https://t.com",
			point:     Point{Kind: PathAppend},
			wantPath:  "/" + pay,
			wantQuery: "",
		},
		{
			name:      "existing encoding in the path is left alone",
			url:       "https://t.com/a%20b/c",
			point:     Point{Kind: PathAppend},
			wantPath:  "/a%20b/c" + pay,
			wantQuery: "",
		},
		{
			name:      "valueless parameter gains an equals sign",
			url:       "https://t.com/p?flag",
			point:     Point{Kind: QueryValue, Param: "flag", index: 0},
			wantPath:  "/p",
			wantQuery: "flag=" + pay,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(mustParse(t, tc.url), "", tc.point, pay)
			if got.Path != tc.wantPath {
				t.Errorf("path  = %q, want %q", got.Path, tc.wantPath)
			}
			if got.Query != tc.wantQuery {
				t.Errorf("query = %q, want %q", got.Query, tc.wantQuery)
			}
		})
	}
}

// A request target beginning with "//" is read as protocol-relative and would
// make net/http send an absolute-form request line.
func TestBuildNeverEmitsProtocolRelativePath(t *testing.T) {
	got := Build(mustParse(t, "https://t.com//"), "", Point{Kind: PathSlash}, pay)
	if len(got.Path) > 1 && got.Path[1] == '/' {
		t.Errorf("path = %q, must not start with //", got.Path)
	}
}

func TestPointsFindsEveryQueryParameter(t *testing.T) {
	u := mustParse(t, "https://t.com/p?a=1&b=2&c=3")
	pts := Points(u, "", []Kind{QueryValue})
	if len(pts) != 3 {
		t.Fatalf("points = %d, want 3", len(pts))
	}
	for i, want := range []string{"a", "b", "c"} {
		if pts[i].Param != want {
			t.Errorf("point %d param = %q, want %q", i, pts[i].Param, want)
		}
	}
}

func TestPointsOrdersByRequestedKinds(t *testing.T) {
	u := mustParse(t, "https://t.com/p?a=1")
	pts := Points(u, "", []Kind{PathAppend, QueryValue})
	if len(pts) != 2 || pts[0].Kind != PathAppend || pts[1].Kind != QueryValue {
		t.Errorf("ordering not respected: %+v", pts)
	}
}

// Splicing a payload into JSON or XML only breaks the parse, so those bodies
// are left alone.
func TestBodyInjectionOnlyForFormEncoded(t *testing.T) {
	u := mustParse(t, "https://t.com/p")
	for _, body := range []string{`{"a":"1"}`, `[1,2]`, `<x>1</x>`, ""} {
		if pts := Points(u, body, []Kind{BodyValue}); len(pts) != 0 {
			t.Errorf("body %q produced %d injection points, want 0", body, len(pts))
		}
	}
	pts := Points(u, "a=1&b=2", []Kind{BodyValue})
	if len(pts) != 2 {
		t.Fatalf("form body produced %d points, want 2", len(pts))
	}
	got := Build(u, "a=1&b=2", pts[1], pay)
	if got.Body != "a=1&b=2"+pay {
		t.Errorf("body = %q", got.Body)
	}
}

func TestParseKinds(t *testing.T) {
	if got, err := ParseKinds(""); err != nil || len(got) != len(AllKinds) {
		t.Errorf("empty should mean all kinds: %v %v", got, err)
	}
	got, err := ParseKinds("query, path")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != QueryValue || got[1] != PathAppend {
		t.Errorf("got %v", got)
	}
	if _, err := ParseKinds("nonsense"); err == nil {
		t.Error("unknown sink accepted")
	}
}
