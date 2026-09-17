package sip

import (
	"strings"
	"testing"
)

func TestNormalizeAlgorithm(t *testing.T) {
	cases := map[string]string{
		"md5": AlgoMD5, "MD5": AlgoMD5,
		"SHA-256": AlgoSHA256, "sha256": AlgoSHA256,
		"sm3": AlgoSM3, "SM3": AlgoSM3,
		"bogus": "",
	}
	for in, want := range cases {
		if got := NormalizeAlgorithm(in); got != want {
			t.Errorf("NormalizeAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDigestRoundTripMD5(t *testing.T) {
	v := NewDigestVerifier([]byte("test-secret"))
	chal := v.NewChallenge("34020000001320000001", "34020000002000000001", AlgoMD5)
	resp := ComputeDigestResponse("34020000001320000001", chal.Realm, "12345678",
		"REGISTER", "sip:34020000002000000001", chal.Nonce, "", "", "", AlgoMD5)
	auth := `Digest username="34020000001320000001", realm="` + chal.Realm +
		`", nonce="` + chal.Nonce + `", uri="sip:34020000002000000001", response="` + resp + `", algorithm=MD5`
	ok, alg, kind := v.Verify(auth, "REGISTER", "sip:34020000002000000001", "34020000001320000001", "12345678")
	if !ok || alg != AlgoMD5 || kind != "" {
		t.Fatalf("MD5 鉴权应通过: ok=%v alg=%s kind=%s", ok, alg, kind)
	}
}

func TestDigestRoundTripSM3(t *testing.T) {
	v := NewDigestVerifier(nil)
	chal := v.NewChallenge("34020000001320000001", "realm-x", AlgoSM3)
	resp := ComputeDigestResponse("34020000001320000001", chal.Realm, "pass", "REGISTER", "sip:srv", chal.Nonce, "", "", "", AlgoSM3)
	auth := `Digest username="34020000001320000001", realm="` + chal.Realm +
		`", nonce="` + chal.Nonce + `", uri="sip:srv", response="` + resp + `", algorithm=SM3`
	ok, alg, _ := v.Verify(auth, "REGISTER", "sip:srv", "34020000001320000001", "pass")
	if !ok || alg != AlgoSM3 {
		t.Fatalf("SM3 鉴权应通过: ok=%v alg=%s", ok, alg)
	}
}

func TestDigestMismatch(t *testing.T) {
	v := NewDigestVerifier(nil)
	chal := v.NewChallenge("dev", "realm", AlgoMD5)
	resp := ComputeDigestResponse("dev", chal.Realm, "right", "REGISTER", "sip:srv", chal.Nonce, "", "", "", AlgoMD5)
	auth := `Digest username="dev", nonce="` + chal.Nonce + `", uri="sip:srv", response="` + resp + `"`
	ok, _, kind := v.Verify(auth, "REGISTER", "sip:srv", "dev", "wrong")
	if ok || kind != "mismatch" {
		t.Fatalf("错误密码应 mismatch: ok=%v kind=%s", ok, kind)
	}
	if v.FailureCount("dev") != 1 {
		t.Errorf("失败计数应累加")
	}
}

func TestDigestUnknownNonce(t *testing.T) {
	v := NewDigestVerifier(nil)
	auth := `Digest username="dev", nonce="no-such", uri="sip:srv", response="x"`
	ok, _, kind := v.Verify(auth, "REGISTER", "sip:srv", "dev", "p")
	if ok || kind != "unknown_nonce" {
		t.Fatalf("未知 nonce 应 unknown_nonce: %s", kind)
	}
}

func TestRedactAuth(t *testing.T) {
	raw := "REGISTER sip:x SIP/2.0\r\nAuthorization: Digest username=\"u\", response=\"secret\"\r\nContent-Length: 0\r\n\r\n"
	got := RedactAuth(raw)
	if strings.Contains(got, "secret") {
		t.Errorf("Authorization 值应被擦除: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("应有 [REDACTED] 标记")
	}
}
