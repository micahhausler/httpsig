// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/micahhausler/sfv"
)

// exampleTarget builds a target from the example message fragment of RFC
// 9421 Section 2.1 plus assorted fields used by other examples.
func exampleTarget() *target {
	req := &http.Request{
		Method: "POST",
		Host:   "www.example.com",
		URL:    &url.URL{Path: "/path", RawQuery: "param=value"},
		Header: http.Header{
			"Date":              {"Tue, 20 Apr 2021 02:07:56 GMT"},
			"X-Ows-Header":      {"   Leading and trailing whitespace.   "},
			"X-Obs-Fold-Header": {"Obsolete\r\n    line folding."},
			"Cache-Control":     {"max-age=60", "   must-revalidate"},
			"Example-Dict":      {"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
			"X-Empty-Header":    {""},
			"Example-Header":    {"value, with, lots", "of, commas"},
		},
	}
	return newTarget(req, "", "", map[string]FieldType{"example-dict": FieldTypeDictionary})
}

func TestFieldCanonicalization(t *testing.T) {
	// Section 2.1 examples.
	tests := []struct {
		c    Component
		want string
	}{
		{Component{Name: "host"}, "www.example.com"},
		{Component{Name: "date"}, "Tue, 20 Apr 2021 02:07:56 GMT"},
		{Component{Name: "x-ows-header"}, "Leading and trailing whitespace."},
		{Component{Name: "x-obs-fold-header"}, "Obsolete line folding."},
		{Component{Name: "cache-control"}, "max-age=60, must-revalidate"},
		{Component{Name: "example-dict"}, "a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
		{Component{Name: "x-empty-header"}, ""},
		// Section 2.1.1: strict structured field serialization.
		{Component{Name: "example-dict", SF: true}, "a=1, b=2;x=1;y=2, c=(a b c)"},
		// Section 2.1.3: binary-wrapped fields.
		{Component{Name: "example-header", BS: true}, ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"},
	}
	tgt := exampleTarget()
	for _, tt := range tests {
		got, err := tgt.componentValue(tt.c)
		if err != nil {
			t.Errorf("componentValue(%+v): %v", tt.c, err)
			continue
		}
		if got != tt.want {
			t.Errorf("componentValue(%+v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestDictionaryMembers(t *testing.T) {
	// Section 2.1.2 examples.
	req := &http.Request{
		URL: &url.URL{},
		Header: http.Header{
			"Example-Dict": {"a=1, b=2;x=1;y=2, c=(a   b    c), d"},
		},
	}
	tgt := newTarget(req, "", "", nil)
	tests := []struct {
		key  string
		want string
	}{
		{"a", "1"},
		{"d", "?1"},
		{"b", "2;x=1;y=2"},
		{"c", "(a b c)"},
	}
	for _, tt := range tests {
		got, err := tgt.componentValue(Component{Name: "example-dict", Key: tt.key})
		if err != nil {
			t.Errorf("key %q: %v", tt.key, err)
			continue
		}
		if got != tt.want {
			t.Errorf("key %q = %q, want %q", tt.key, got, tt.want)
		}
	}
	if _, err := tgt.componentValue(Component{Name: "example-dict", Key: "q"}); err == nil {
		t.Error("missing dictionary key: no error")
	}
}

func TestBinaryWrapSingleInstance(t *testing.T) {
	// Section 2.1.3: the single-instance encoding must differ from the
	// multiple-instance encoding.
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{"Example-Header": {"value, with, lots, of, commas"}},
	}
	tgt := newTarget(req, "", "", nil)
	got, err := tgt.componentValue(Component{Name: "example-header", BS: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDerivedComponents(t *testing.T) {
	// Section 2.2 examples.
	req := readRequest(t, "POST /path?param=value HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	tgt := newTarget(req, "https", "", nil)
	tests := []struct {
		name string
		want string
	}{
		{"@method", "POST"},
		{"@target-uri", "https://www.example.com/path?param=value"},
		{"@authority", "www.example.com"},
		{"@scheme", "https"},
		{"@request-target", "/path?param=value"},
		{"@path", "/path"},
		{"@query", "?param=value"},
	}
	for _, tt := range tests {
		got, err := tgt.componentValue(Component{Name: tt.name})
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAuthorityNormalization(t *testing.T) {
	// Section 2.2.3: lowercase host, default port omitted.
	tests := []struct {
		host, scheme, want string
	}{
		{"EXAMPLE.com", "https", "example.com"},
		{"example.com:443", "https", "example.com"},
		{"example.com:80", "http", "example.com"},
		{"example.com:8080", "https", "example.com:8080"},
		{"example.com:443", "http", "example.com:443"},
	}
	for _, tt := range tests {
		req := &http.Request{URL: &url.URL{}, Host: tt.host}
		tgt := newTarget(req, tt.scheme, "", nil)
		got, err := tgt.componentValue(Component{Name: "@authority"})
		if err != nil {
			t.Errorf("%s %s: %v", tt.scheme, tt.host, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s %s = %q, want %q", tt.scheme, tt.host, got, tt.want)
		}
	}
}

func TestEmptyPathAndQuery(t *testing.T) {
	// Sections 2.2.6 and 2.2.7: empty path is "/", absent query is "?".
	req := &http.Request{URL: &url.URL{}, Host: "example.com"}
	tgt := newTarget(req, "", "", nil)
	if got, _ := tgt.componentValue(Component{Name: "@path"}); got != "/" {
		t.Errorf("@path = %q, want /", got)
	}
	if got, _ := tgt.componentValue(Component{Name: "@query"}); got != "?" {
		t.Errorf("@query = %q, want ?", got)
	}
}

func TestQueryParam(t *testing.T) {
	// Section 2.2.8 examples.
	req := readRequest(t, "GET /path?param=value&foo=bar&baz=batman&qux= HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	tgt := newTarget(req, "", "", nil)
	tests := []struct {
		param, want string
	}{
		{"baz", "batman"},
		{"qux", ""},
		{"param", "value"},
	}
	for _, tt := range tests {
		got, err := tgt.componentValue(Component{Name: "@query-param", QueryParam: tt.param})
		if err != nil {
			t.Errorf("%s: %v", tt.param, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s = %q, want %q", tt.param, got, tt.want)
		}
	}
	if _, err := tgt.componentValue(Component{Name: "@query-param", QueryParam: "nope"}); err == nil {
		t.Error("missing query parameter: no error")
	}
}

func TestQueryParamEncoding(t *testing.T) {
	// Section 2.2.8: values are decoded and re-encoded.
	req := readRequest(t, "GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&"+
		"bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something HTTP/1.1\r\n"+
		"Host: www.example.com\r\n\r\n")
	tgt := newTarget(req, "", "", nil)
	tests := []struct {
		param, want string
	}{
		{"var", "this%20is%20a%20big%0Amultiline%20value"},
		{"bar", "with%20plus%20whitespace"},
		{"fa%C3%A7ade%22%3A%20", "something"},
	}
	for _, tt := range tests {
		got, err := tgt.componentValue(Component{Name: "@query-param", QueryParam: tt.param})
		if err != nil {
			t.Errorf("%s: %v", tt.param, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s = %q, want %q", tt.param, got, tt.want)
		}
	}
}

func TestRepeatedQueryParam(t *testing.T) {
	// Section 2.2.8: repeated parameters must not be included.
	req := &http.Request{URL: &url.URL{RawQuery: "a=1&a=2"}, Host: "example.com"}
	tgt := newTarget(req, "", "", nil)
	if _, err := tgt.componentValue(Component{Name: "@query-param", QueryParam: "a"}); err == nil {
		t.Error("repeated query parameter: no error")
	}
}

func TestComponentValidation(t *testing.T) {
	tests := []struct {
		name string
		c    Component
	}{
		{"@status", Component{Name: "@status"}},
		{"@signature-params", Component{Name: "@signature-params"}},
		{"unknown derived", Component{Name: "@nope"}},
		{"empty", Component{}},
		{"uppercase field", Component{Name: "Content-Type"}},
		{"bs with sf", Component{Name: "x", BS: true, SF: true}},
		{"bs with key", Component{Name: "x", BS: true, Key: "a"}},
		{"query-param without name", Component{Name: "@query-param"}},
		{"name on field", Component{Name: "x", QueryParam: "a"}},
		{"name on other derived", Component{Name: "@method", QueryParam: "a"}},
		{"key on derived", Component{Name: "@method", Key: "a"}},
	}
	for _, tt := range tests {
		if err := tt.c.validate(); err == nil {
			t.Errorf("%s: no error", tt.name)
		}
	}
}

func TestHostFieldVerbatim(t *testing.T) {
	// The host field falls back to Request.Host verbatim: unlike
	// @authority, it is not lowercased and keeps the port. This test also
	// pins the net/http property the fallback depends on: ReadRequest
	// moves the Host header out of the header map, so a header entry
	// cannot shadow the wire value.
	req := readRequest(t, "GET / HTTP/1.1\r\nHost: EXAMPLE.com:8443\r\n\r\n")
	if h := req.Header.Values("Host"); len(h) != 0 {
		t.Fatalf("Header[Host] = %v, want empty", h)
	}
	tgt := newTarget(req, "https", "", nil)
	if got, _ := tgt.componentValue(Component{Name: "host"}); got != "EXAMPLE.com:8443" {
		t.Errorf("host = %q, want EXAMPLE.com:8443", got)
	}
	if got, _ := tgt.componentValue(Component{Name: "@authority"}); got != "example.com:8443" {
		t.Errorf("@authority = %q, want example.com:8443", got)
	}
}

func TestMissingField(t *testing.T) {
	req := &http.Request{URL: &url.URL{}, Host: "example.com"}
	tgt := newTarget(req, "", "", nil)
	if _, err := tgt.componentValue(Component{Name: "x-missing"}); err == nil {
		t.Error("missing field: no error")
	}
}

func TestUnknownStructuredFieldType(t *testing.T) {
	// Section 2.1.1: the sf flag errors when the type is not known.
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{"X-Thing": {"a"}},
		Host:   "example.com",
	}
	tgt := newTarget(req, "", "", nil)
	if _, err := tgt.componentValue(Component{Name: "x-thing", SF: true}); err == nil {
		t.Error("unknown structured field type: no error")
	}
}

func TestNonASCIIFieldValue(t *testing.T) {
	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{"X-Latin": {"caf\xc3\xa9"}},
		Host:   "example.com",
	}
	tgt := newTarget(req, "", "", nil)
	ids := []covered{{id: Component{Name: "x-latin"}.identifier(), c: Component{Name: "x-latin"}}}
	if _, err := signatureBase(tgt, ids, innerListOf(ids)); err == nil {
		t.Error("non-ASCII field value: no error")
	}
}

func TestDuplicateComponent(t *testing.T) {
	// Section 2.5 step 2.1.
	req := &http.Request{URL: &url.URL{}, Host: "example.com", Method: "GET"}
	tgt := newTarget(req, "", "", nil)
	c := Component{Name: "@method"}
	ids := []covered{{id: c.identifier(), c: c}, {id: c.identifier(), c: c}}
	if _, err := signatureBase(tgt, ids, innerListOf(ids)); err == nil {
		t.Error("duplicate component: no error")
	}
}

func TestObsFoldValue(t *testing.T) {
	if got := canonicalFieldValue("Obsolete\r\n line folding."); got != "Obsolete line folding." {
		t.Errorf("got %q", got)
	}
	if got := canonicalFieldValue("no folding"); got != "no folding" {
		t.Errorf("got %q", got)
	}
}

func TestSchemeDefaults(t *testing.T) {
	req := &http.Request{URL: &url.URL{}, Host: "example.com"}
	if tgt := newTarget(req, "", "", nil); tgt.scheme != "http" {
		t.Errorf("scheme = %q, want http", tgt.scheme)
	}
	req.TLS = &tls.ConnectionState{}
	if tgt := newTarget(req, "", "", nil); tgt.scheme != "https" {
		t.Errorf("scheme = %q, want https", tgt.scheme)
	}
	if tgt := newTarget(req, "HTTP", "EXAMPLE.com", nil); tgt.scheme != "http" || tgt.authority != "example.com" {
		t.Errorf("overrides: scheme=%q authority=%q", tgt.scheme, tgt.authority)
	}
}

func TestRequestTargetForms(t *testing.T) {
	// Section 2.2.5: the value follows the request target form.
	req := readRequest(t, "OPTIONS * HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
	tgt := newTarget(req, "", "", nil)
	if got, _ := tgt.componentValue(Component{Name: "@request-target"}); got != "*" {
		t.Errorf("asterisk-form = %q, want *", got)
	}
	// Outbound requests have no RequestURI; origin form is derived.
	out := &http.Request{URL: &url.URL{Path: "/path", RawQuery: "q=1"}, Host: "example.com"}
	tgt = newTarget(out, "", "", nil)
	if got, _ := tgt.componentValue(Component{Name: "@request-target"}); got != "/path?q=1" {
		t.Errorf("origin-form = %q, want /path?q=1", got)
	}
}

// innerListOf builds the @signature-params inner list for a covered set,
// with no parameters.
func innerListOf(ids []covered) sfv.InnerList {
	il := sfv.InnerList{}
	for _, cc := range ids {
		il.Items = append(il.Items, cc.id)
	}
	return il
}

func TestParseComponent(t *testing.T) {
	tests := []struct {
		in   string
		want Component
		err  bool
	}{
		{in: `"@method"`, want: Component{Name: "@method"}},
		{in: `"content-digest"`, want: Component{Name: "content-digest"}},
		{in: `"@query-param";name="q"`, want: Component{Name: "@query-param", QueryParam: "q"}},
		{in: `"example-dict";key="a"`, want: Component{Name: "example-dict", Key: "a"}},
		{in: `"example-header";bs`, want: Component{Name: "example-header", BS: true}},
		{in: `"example-dict";sf`, want: Component{Name: "example-dict", SF: true}},
		{in: `@method`, err: true},        // bare form: not a quoted string
		{in: `"@status"`, err: true},      // response-only
		{in: `"@method";req`, err: true},  // req parameter unsupported
		{in: `"Content-Type"`, err: true}, // not lowercase
		{in: `"@nope"`, err: true},        // unknown derived component
		{in: ``, err: true},
	}
	for _, tt := range tests {
		got, err := ParseComponent(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("ParseComponent(%q) = %+v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseComponent(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseComponent(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}
