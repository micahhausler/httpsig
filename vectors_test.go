// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Keys from RFC 9421 Appendix B.1. They must not be used for any purpose
// other than testing.
const (
	testKeyRSAPub = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`

	testKeyRSAPriv = `-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`

	testKeyRSAPSSPub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`

	testKeyRSAPSSPriv = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----`

	testKeyECCP256Pub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`

	testKeyECCP256Priv = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`

	testKeyEd25519Pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`

	testKeyEd25519Priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`

	testSharedSecret = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
)

func pemBytes(t *testing.T, s string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

func rsaTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := x509.ParsePKCS1PrivateKey(pemBytes(t, testKeyRSAPriv))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKCS1PublicKey(pemBytes(t, testKeyRSAPub))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// rsaPSSTestKeys parses the test-key-rsa-pss pair. The private key's PKCS#8
// wrapper uses the id-RSASSA-PSS algorithm, which crypto/x509 does not
// support, so the inner PKCS#1 key is unwrapped by hand.
func rsaPSSTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	var wrapper struct {
		Version    int
		Algo       asn1.RawValue
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(pemBytes(t, testKeyRSAPSSPriv), &wrapper); err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS1PrivateKey(wrapper.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pemBytes(t, testKeyRSAPSSPub))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub.(*rsa.PublicKey)
}

func eccTestKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := x509.ParseECPrivateKey(pemBytes(t, testKeyECCP256Priv))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pemBytes(t, testKeyECCP256Pub))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub.(*ecdsa.PublicKey)
}

func ed25519TestKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv, err := x509.ParsePKCS8PrivateKey(pemBytes(t, testKeyEd25519Priv))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pemBytes(t, testKeyEd25519Pub))
	if err != nil {
		t.Fatal(err)
	}
	return priv.(ed25519.PrivateKey), pub.(ed25519.PublicKey)
}

func sharedSecret(t *testing.T) []byte {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func verifier(t *testing.T, alg Algorithm, key any) Verifier {
	t.Helper()
	v, err := NewVerifier(alg, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signer(t *testing.T, alg Algorithm, key any) Signer {
	t.Helper()
	s, err := NewSigner(alg, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// readRequest parses a raw HTTP/1.1 request the way a server would receive
// it.
func readRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

const contentDigest = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"

// testRequest is the test-request message from RFC 9421 Appendix B.2.
func testRequest(t *testing.T) *http.Request {
	return readRequest(t, "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n"+
		"Host: example.com\r\n"+
		"Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Digest: "+contentDigest+"\r\n"+
		"Content-Length: 18\r\n"+
		"\r\n"+
		`{"hello": "world"}`)
}

// parseOne parses the request's signatures and returns the one with the
// given label.
func parseOne(t *testing.T, req *http.Request, label string) *Signature {
	t.Helper()
	return parseOneOpts(t, req, label, nil)
}

func TestVectorB21(t *testing.T) {
	req := testRequest(t)
	req.Header.Set("Signature-Input", `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`)
	req.Header.Set("Signature", "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem"+
		"LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG"+
		"52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx"+
		"2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6"+
		"UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3"+
		"+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:")

	sig := parseOne(t, req, "sig-b21")
	wantBase := `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`
	if got := string(sig.base); got != wantBase {
		t.Errorf("base = %q, want %q", got, wantBase)
	}
	if sig.KeyID() != "test-key-rsa-pss" {
		t.Errorf("KeyID = %q", sig.KeyID())
	}
	if sig.Nonce() != "b3k2pp5k7z-50gnwp.yemd" {
		t.Errorf("Nonce = %q", sig.Nonce())
	}
	if !sig.Created().Equal(time.Unix(1618884473, 0)) {
		t.Errorf("Created = %v", sig.Created())
	}
	_, pub := rsaPSSTestKeys(t)
	if err := sig.Verify(verifier(t, RSAPSSSHA512, pub), testPolicy()); err != nil {
		t.Error(err)
	}
}

func TestVectorB22(t *testing.T) {
	req := testRequest(t)
	req.Header.Set("Signature-Input", `sig-b22=("@authority" "content-digest" `+
		`"@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`)
	req.Header.Set("Signature", "sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ"+
		"EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT"+
		"8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA"+
		"RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd"+
		"4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK"+
		"UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:")

	sig := parseOne(t, req, "sig-b22")
	wantBase := `"@authority": example.com` + "\n" +
		`"content-digest": ` + contentDigest + "\n" +
		`"@query-param";name="Pet": dog` + "\n" +
		`"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet")` +
		`;created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`
	if got := string(sig.base); got != wantBase {
		t.Errorf("base = %q, want %q", got, wantBase)
	}
	if sig.Tag() != "header-example" {
		t.Errorf("Tag = %q", sig.Tag())
	}
	_, pub := rsaPSSTestKeys(t)
	if err := sig.Verify(verifier(t, RSAPSSSHA512, pub), testPolicy()); err != nil {
		t.Error(err)
	}
}

func TestVectorB23(t *testing.T) {
	req := testRequest(t)
	req.Header.Set("Signature-Input", `sig-b23=("date" "@method" "@path" "@query" `+
		`"@authority" "content-type" "content-digest" "content-length")`+
		`;created=1618884473;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB"+
		"iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU"+
		"xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1"+
		"pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9"+
		"bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z"+
		"JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:")

	sig := parseOne(t, req, "sig-b23")
	wantBase := `"date": Tue, 20 Apr 2021 02:07:55 GMT` + "\n" +
		`"@method": POST` + "\n" +
		`"@path": /foo` + "\n" +
		`"@query": ?param=Value&Pet=dog` + "\n" +
		`"@authority": example.com` + "\n" +
		`"content-type": application/json` + "\n" +
		`"content-digest": ` + contentDigest + "\n" +
		`"content-length": 18` + "\n" +
		`"@signature-params": ("date" "@method" "@path" "@query" "@authority" ` +
		`"content-type" "content-digest" "content-length")` +
		`;created=1618884473;keyid="test-key-rsa-pss"`
	if got := string(sig.base); got != wantBase {
		t.Errorf("base = %q, want %q", got, wantBase)
	}
	_, pub := rsaPSSTestKeys(t)
	if err := sig.Verify(verifier(t, RSAPSSSHA512, pub), testPolicy()); err != nil {
		t.Error(err)
	}
}

func TestVectorB25(t *testing.T) {
	wantInput := `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`
	wantSig := "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"

	req := testRequest(t)
	req.Header.Set("Signature-Input", wantInput)
	req.Header.Set("Signature", wantSig)
	sig := parseOne(t, req, "sig-b25")
	if err := sig.Verify(verifier(t, HMACSHA256, sharedSecret(t)), testPolicy()); err != nil {
		t.Error(err)
	}

	// HMAC is deterministic: signing must reproduce the vector exactly.
	req = testRequest(t)
	err := Sign(req, signer(t, HMACSHA256, sharedSecret(t)), SignOptions{
		Components: []Component{{Name: "date"}, {Name: "@authority"}, {Name: "content-type"}},
		Label:      "sig-b25",
		Created:    time.Unix(1618884473, 0),
		KeyID:      "test-shared-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Signature-Input"); got != wantInput {
		t.Errorf("Signature-Input = %q, want %q", got, wantInput)
	}
	if got := req.Header.Get("Signature"); got != wantSig {
		t.Errorf("Signature = %q, want %q", got, wantSig)
	}
}

func TestVectorB26(t *testing.T) {
	wantInput := `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")` +
		`;created=1618884473;keyid="test-key-ed25519"`
	wantSig := "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1" +
		"u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"

	req := testRequest(t)
	req.Header.Set("Signature-Input", wantInput)
	req.Header.Set("Signature", wantSig)
	sig := parseOne(t, req, "sig-b26")
	_, pub := ed25519TestKeys(t)
	if err := sig.Verify(verifier(t, Ed25519, pub), testPolicy()); err != nil {
		t.Error(err)
	}

	// Ed25519 is deterministic: signing must reproduce the vector exactly.
	req = testRequest(t)
	priv, _ := ed25519TestKeys(t)
	err := Sign(req, signer(t, Ed25519, priv), SignOptions{
		Components: []Component{
			{Name: "date"}, {Name: "@method"}, {Name: "@path"},
			{Name: "@authority"}, {Name: "content-type"}, {Name: "content-length"},
		},
		Label:   "sig-b26",
		Created: time.Unix(1618884473, 0),
		KeyID:   "test-key-ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Signature-Input"); got != wantInput {
		t.Errorf("Signature-Input = %q, want %q", got, wantInput)
	}
	if got := req.Header.Get("Signature"); got != wantSig {
		t.Errorf("Signature = %q, want %q", got, wantSig)
	}
}

// TestVectorSection32 checks the worked example of Sections 2.5 and 3.2,
// including the Figure 1 signature base.
func TestVectorSection32(t *testing.T) {
	req := testRequest(t)
	req.Header.Set("Signature-Input", `sig1=("@method" "@authority" "@path" `+
		`"content-digest" "content-length" "content-type")`+
		`;created=1618884473;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrl"+
		"FrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxH"+
		"LMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSf"+
		"SvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y"+
		"9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7"+
		"aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:")

	sig := parseOne(t, req, "sig1")
	wantBase := `"@method": POST` + "\n" +
		`"@authority": example.com` + "\n" +
		`"@path": /foo` + "\n" +
		`"content-digest": ` + contentDigest + "\n" +
		`"content-length": 18` + "\n" +
		`"content-type": application/json` + "\n" +
		`"@signature-params": ("@method" "@authority" "@path" ` +
		`"content-digest" "content-length" "content-type")` +
		`;created=1618884473;keyid="test-key-rsa-pss"`
	if got := string(sig.base); got != wantBase {
		t.Errorf("base = %q, want %q", got, wantBase)
	}
	_, pub := rsaPSSTestKeys(t)
	if err := sig.Verify(verifier(t, RSAPSSSHA512, pub), testPolicy()); err != nil {
		t.Error(err)
	}
}

// TestVectorB3 checks the TLS-terminating proxy example of Appendix B.3.
func TestVectorB3(t *testing.T) {
	clientCert := ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKD" +
		"BJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQT" +
		"AeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFk" +
		"wEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmck" +
		"C8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDV" +
		"R0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf" +
		"8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV" +
		"4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6" +
		"bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:"
	req := readRequest(t, "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n"+
		"Host: service.internal.example\r\n"+
		"Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: 18\r\n"+
		"Client-Cert: "+clientCert+"\r\n"+
		"Signature-Input: ttrp=(\"@path\" \"@query\" \"@method\" \"@authority\" "+
		"\"client-cert\");created=1618884473;keyid=\"test-key-ecc-p256\"\r\n"+
		"Signature: ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6"+
		"Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:\r\n"+
		"\r\n"+
		`{"hello": "world"}`)

	sig := parseOne(t, req, "ttrp")
	wantBase := `"@path": /foo` + "\n" +
		`"@query": ?param=Value&Pet=dog` + "\n" +
		`"@method": POST` + "\n" +
		`"@authority": service.internal.example` + "\n" +
		`"client-cert": ` + clientCert + "\n" +
		`"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert")` +
		`;created=1618884473;keyid="test-key-ecc-p256"`
	if got := string(sig.base); got != wantBase {
		t.Errorf("base = %q, want %q", got, wantBase)
	}
	_, pub := eccTestKeys(t)
	if err := sig.Verify(verifier(t, ECDSAP256SHA256, pub), testPolicy()); err != nil {
		t.Error(err)
	}
}

// TestVectorB4 checks the message transformation examples of Appendix B.4.
func TestVectorB4(t *testing.T) {
	const signatureFields = "Signature-Input: transform=(\"@method\" \"@path\" \"@authority\" " +
		"\"accept\");created=1618884473;keyid=\"test-key-ed25519\"\r\n" +
		"Signature: transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5J" +
		"Z1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:\r\n"
	tests := []struct {
		name  string
		raw   string
		valid bool
	}{
		{"original", "GET /demo?name1=Value1&Name2=value2 HTTP/1.1\r\n" +
			"Host: example.org\r\n" +
			"Date: Fri, 15 Jul 2022 14:24:55 GMT\r\n" +
			"Accept: application/json\r\n" +
			"Accept: */*\r\n" +
			signatureFields + "\r\n", true},
		{"added fields and query param", "GET /demo?name1=Value1&Name2=value2&param=added HTTP/1.1\r\n" +
			"Host: example.org\r\n" +
			"Date: Fri, 15 Jul 2022 14:24:55 GMT\r\n" +
			"Accept: application/json\r\n" +
			"Accept: */*\r\n" +
			"Accept-Language: en-US,en;q=0.5\r\n" +
			signatureFields + "\r\n", true},
		{"collapsed accept", "GET /demo?name1=Value1&Name2=value2 HTTP/1.1\r\n" +
			"Host: example.org\r\n" +
			"Referer: https://developer.example.org/demo\r\n" +
			"Accept: application/json, */*\r\n" +
			signatureFields + "\r\n", true},
		{"reordered fields", "GET /demo?name1=Value1&Name2=value2 HTTP/1.1\r\n" +
			"Accept: application/json\r\n" +
			"Accept: */*\r\n" +
			"Date: Fri, 15 Jul 2022 14:24:55 GMT\r\n" +
			"Host: example.org\r\n" +
			signatureFields + "\r\n", true},
		{"changed method and authority", "POST /demo?name1=Value1&Name2=value2 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Date: Fri, 15 Jul 2022 14:24:55 GMT\r\n" +
			"Accept: application/json\r\n" +
			"Accept: */*\r\n" +
			signatureFields + "\r\n", false},
		{"reordered accept values", "GET /demo?name1=Value1&Name2=value2 HTTP/1.1\r\n" +
			"Host: example.org\r\n" +
			"Date: Fri, 15 Jul 2022 14:24:55 GMT\r\n" +
			"Accept: */*\r\n" +
			"Accept: application/json\r\n" +
			signatureFields + "\r\n", false},
	}
	_, pub := ed25519TestKeys(t)
	key := verifier(t, Ed25519, pub)
	wantBase := `"@method": GET` + "\n" +
		`"@path": /demo` + "\n" +
		`"@authority": example.org` + "\n" +
		`"accept": application/json, */*` + "\n" +
		`"@signature-params": ("@method" "@path" "@authority" "accept")` +
		`;created=1618884473;keyid="test-key-ed25519"`
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := parseOne(t, readRequest(t, tt.raw), "transform")
			err := sig.Verify(key, testPolicy())
			if tt.valid && err != nil {
				t.Errorf("Verify: %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrSignatureMismatch) {
				t.Errorf("Verify = %v, want ErrSignatureMismatch", err)
			}
			if tt.name == "original" && string(sig.base) != wantBase {
				t.Errorf("base = %q, want %q", sig.base, wantBase)
			}
		})
	}
}

// testPolicy pins the verification time to the era of the RFC's test
// vectors.
func testPolicy() Policy {
	return Policy{Now: func() time.Time { return time.Unix(1618884473, 0) }}
}
