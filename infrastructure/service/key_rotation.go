package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/RanguraGIT/sso/domain/vo"
	"github.com/golang-jwt/jwt/v5"

)

// jwkKey minimal JWK representation for RSA public key (modulus/exponent base64url) for JWKS endpoint.
type jwkKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []jwkKey `json:"keys"`
}

type keyRecord struct {
	kid       string
	key       *rsa.PrivateKey
	createdAt time.Time
}

type InMemoryKeyRotation struct {
	mu          sync.RWMutex
	active      *keyRecord
	previous    []*keyRecord
	rotateAfter time.Duration
	lastRotate  time.Time
}

func NewInMemoryKeyRotation(ttl time.Duration) *InMemoryKeyRotation {
	kr := &InMemoryKeyRotation{rotateAfter: ttl}
	_ = kr.generateNew() // initial key
	return kr
}

func (k *InMemoryKeyRotation) generateNew() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rec := &keyRecord{kid: randomKID(8), key: priv, createdAt: time.Now().UTC()}
	if k.active != nil {
		k.previous = append(k.previous, k.active)
	}
	k.active = rec
	k.lastRotate = time.Now().UTC()
	return nil
}

func (k *InMemoryKeyRotation) CurrentKeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return ""
	}
	return k.active.kid
}

func (k *InMemoryKeyRotation) RotateIfNeeded(_ context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.lastRotate) < k.rotateAfter {
		return nil
	}
	return k.generateNew()
}

func (k *InMemoryKeyRotation) SigningKey() (*rsa.PrivateKey, string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return nil, "", errors.New("no active key")
	}
	return k.active.key, k.active.kid, nil
}

func (k *InMemoryKeyRotation) GetPublicJWKS(_ context.Context) (any, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var keys []jwkKey
	add := func(rec *keyRecord) {
		if rec == nil {
			return
		}
		pub := rec.key.PublicKey
		nBytes := pub.N.Bytes()
		e := pub.E
		keys = append(keys, jwkKey{
			Kty: "RSA", Alg: "RS256", Use: "sig", Kid: rec.kid,
			N: base64url(nBytes), E: base64urlFromInt(e),
		})
	}
	add(k.active)
	// Optionally include previous keys until tokens expire (not time-limited in this simple impl)
	for _, p := range k.previous {
		add(p)
	}
	return JWKS{Keys: keys}, nil
}

// Proper base64url without padding for JWK fields.
func base64url(b []byte) string     { return base64.RawURLEncoding.EncodeToString(b) }
func base64urlFromInt(i int) string { return base64url(intToBytes(i)) }

func intToBytes(i int) []byte { return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)} }

// randomKID naive placeholder.
func randomKID(n int) string { return time.Now().Format("20060102150405") }

// SignJWT helper to satisfy interface (delegated in token service; here just returns error because we sign in token service).
// For a richer design, move signing here and have token service build claims only.
// SignJWT not used directly (token service signs); returning error keeps interface explicit.
func (k *InMemoryKeyRotation) SignJWT(cl vo.JWTClaims, ttl time.Duration) (string, error) {
	priv, kid, err := k.SigningKey()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	exp := now.Add(ttl).Unix()
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = kid
	token.Claims = jwt.MapClaims{
		"sub":       cl.Subject,
		"aud":       cl.Audience,
		"iss":       cl.Issuer,
		"iat":       now.Unix(),
		"exp":       exp,
		"scope":     cl.Scope,
		"client_id": cl.ClientID,
		"nonce":     cl.Nonce,
	}
	return token.SignedString(priv)
}
