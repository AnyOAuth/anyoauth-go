package anyoauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Error struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func invalid() error           { return &Error{0, "invalid_argument", "Invalid argument"} }

type Client struct {
	base, id, secret string
	http             *http.Client
}

var contract map[string]any

func init() {
	if json.Unmarshal([]byte(`{"schemas":{"Provider":{"type":"string","enum":["google","github"]},"RedirectUri":{"type":"string","format":"uri","maxLength":2048,"x-validation":"redirect","description":"Exact registered HTTPS URL or HTTP loopback; no credentials, query or fragment."},"TokenRequest":{"type":"object","additionalProperties":false,"required":["grant_type","client_id","client_secret","code","redirect_uri","code_verifier"],"properties":{"grant_type":{"type":"string","const":"authorization_code"},"client_id":{"type":"string","maxLength":100},"client_secret":{"type":"string","minLength":1,"maxLength":200},"code":{"type":"string","minLength":1,"maxLength":200},"redirect_uri":{"$ref":"#/components/schemas/RedirectUri"},"code_verifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"}}},"TokenResponse":{"type":"object","required":["access_token","token_type","expires_in","scope"],"properties":{"access_token":{"type":"string","pattern":"^aop_[A-Za-z0-9_-]{43}$"},"token_type":{"type":"string","const":"Bearer"},"expires_in":{"type":"integer","const":900},"scope":{"type":"string","const":"profile"}}},"Profile":{"type":"object","required":["subject","provider","providerSubject","name","username","email","emailVerified","avatarUrl"],"properties":{"subject":{"type":"string"},"provider":{"$ref":"#/components/schemas/Provider"},"providerSubject":{"type":"string"},"name":{"type":["string","null"]},"username":{"type":["string","null"]},"email":{"type":["string","null"]},"emailVerified":{"type":"boolean"},"avatarUrl":{"type":["string","null"]}}},"ProviderStatus":{"type":"object","required":["id","configured","enabled","available"],"properties":{"id":{"$ref":"#/components/schemas/Provider"},"configured":{"type":"boolean"},"enabled":{"type":"boolean"},"available":{"type":"boolean"}}},"ProviderStatuses":{"type":"array","items":{"$ref":"#/components/schemas/ProviderStatus"}},"ApiError":{"type":"object","required":["error"],"properties":{"error":{"type":"string"},"message":{"type":"string"}}},"Transaction":{"type":"object","required":["state","codeVerifier","codeChallenge","createdAt","expiresAt"],"properties":{"state":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"codeVerifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"},"codeChallenge":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"createdAt":{"type":"integer"},"expiresAt":{"type":"integer"}}}},"operations":{"exchangeCode":{"id":"exchangeCode","path":"/v1/token","method":"POST","auth":"client","requestSchema":"TokenRequest","responseSchema":"TokenResponse","successStatus":200,"fields":[{"wire":"grant_type","param":"grantType","value":"authorization_code"},{"wire":"client_id","param":"clientId"},{"wire":"client_secret","param":"clientSecret"},{"wire":"code","param":"code"},{"wire":"redirect_uri","param":"redirectUri"},{"wire":"code_verifier","param":"codeVerifier"}]},"profile":{"id":"profile","path":"/v1/profile","method":"GET","auth":"bearer","requestSchema":null,"responseSchema":"Profile","successStatus":200,"fields":[]},"revoke":{"id":"revoke","path":"/v1/revoke","method":"POST","auth":"bearer","requestSchema":null,"responseSchema":null,"successStatus":204,"fields":[]},"providers":{"id":"providers","path":"/api/providers","method":"GET","auth":"none","requestSchema":null,"responseSchema":"ProviderStatuses","successStatus":200,"fields":[]}}}`), &contract) != nil {
		panic("Invalid generated contract")
	}
}
func NewClient(base, id, secret string) (*Client, error) {
	if base == "" {
		base = "https://api.anyoauth.com"
	}
	if !validURL(base, true) {
		return nil, invalid()
	}
	return &Client{strings.TrimSuffix(base, "/"), id, secret, &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func validURL(raw string, origin bool) bool {
	if !origin && float64(len([]rune(raw))) > contract["schemas"].(map[string]any)["RedirectUri"].(map[string]any)["maxLength"].(float64) {
		return false
	}
	if strings.ContainsAny(raw, "\\\r\n\t ") {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return false
	}
	return !origin || (u.Path == "" || u.Path == "/")
}
func str(p map[string]any, k string) string { s, _ := p[k].(string); return s }
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case json.Number:
		n, e := x.Float64()
		return n, e == nil
	}
	return 0, false
}
func validate(s map[string]any, v any) bool {
	if ref, ok := s["$ref"].(string); ok {
		return validate(contract["schemas"].(map[string]any)[ref[strings.LastIndex(ref, "/")+1:]].(map[string]any), v)
	}
	types := []any{s["type"]}
	if ts, ok := s["type"].([]any); ok {
		types = ts
	}
	good := false
	for _, t := range types {
		switch t {
		case "null":
			good = good || v == nil
		case "string":
			_, ok := v.(string)
			good = good || ok
		case "boolean":
			_, ok := v.(bool)
			good = good || ok
		case "integer":
			n, ok := number(v)
			good = good || (ok && n == float64(int64(n)))
		case "object":
			_, ok := v.(map[string]any)
			good = good || ok
		case "array":
			_, ok := v.([]any)
			good = good || ok
		}
	}
	if !good {
		return false
	}
	if v == nil {
		return true
	}
	if c, ok := s["const"]; ok && fmt.Sprint(c) != fmt.Sprint(v) {
		return false
	}
	if es, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range es {
			found = found || e == v
		}
		if !found {
			return false
		}
	}
	if x, ok := v.(string); ok {
		n := float64(len([]rune(x)))
		if a, ok := s["minLength"].(float64); ok && n < a {
			return false
		}
		if a, ok := s["maxLength"].(float64); ok && n > a {
			return false
		}
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(x) {
			return false
		}
		if s["x-validation"] == "redirect" && !validURL(x, false) {
			return false
		}
	}
	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, k := range req {
				if _, ok := obj[k.(string)]; !ok {
					return false
				}
			}
		}
		for k, x := range obj {
			if desc, ok := props[k].(map[string]any); ok {
				if !validate(desc, x) {
					return false
				}
			} else if s["additionalProperties"] == false {
				return false
			}
		}
	}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if !validate(s["items"].(map[string]any), x) {
				return false
			}
		}
	}
	return true
}
func PKCEChallenge(verifier string) (string, error) {
	if !regexp.MustCompile("^[A-Za-z0-9._~-]{43,128}$").MatchString(verifier) {
		return "", invalid()
	}
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}
func CreateTransaction() (map[string]any, error) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	if _, e := rand.Read(a); e != nil {
		return nil, &Error{0, "crypto_error", "Random source failed"}
	}
	if _, e := rand.Read(b); e != nil {
		return nil, &Error{0, "crypto_error", "Random source failed"}
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	ch, _ := PKCEChallenge(v)
	now := time.Now().Unix()
	return map[string]any{"state": base64.RawURLEncoding.EncodeToString(a), "codeVerifier": v, "codeChallenge": ch, "createdAt": now, "expiresAt": now + 600}, nil
}
func (c *Client) AuthorizationURL(p map[string]any) (string, error) {
	provider, state, ch, redirect := str(p, "provider"), str(p, "state"), str(p, "codeChallenge"), str(p, "redirectUri")
	if !validate(contract["schemas"].(map[string]any)["Provider"].(map[string]any), provider) || len(state) < 16 || len(state) > 512 || !regexp.MustCompile("^[A-Za-z0-9_-]{43}$").MatchString(ch) || !validate(contract["schemas"].(map[string]any)["RedirectUri"].(map[string]any), redirect) || c.id == "" {
		return "", invalid()
	}
	q := url.Values{"client_id": {c.id}, "provider": {provider}, "redirect_uri": {redirect}, "state": {state}, "code_challenge": {ch}, "code_challenge_method": {"S256"}, "response_type": {"code"}}
	return c.base + "/authorize?" + q.Encode(), nil
}
func ValidateCallback(p map[string]any) (map[string]any, error) {
	raw, redirect, state := str(p, "callbackUrl"), str(p, "redirectUri"), str(p, "state")
	expires, ok := number(p["expiresAt"])
	if !ok || expires <= float64(time.Now().Unix()) || expires != float64(int64(expires)) || state == "" || !validate(contract["schemas"].(map[string]any)["RedirectUri"].(map[string]any), redirect) {
		return nil, invalid()
	}
	u, e := url.Parse(raw)
	if e != nil || u.Fragment != "" || strings.Contains(raw, "#") || strings.SplitN(raw, "?", 2)[0] != redirect {
		return nil, invalid()
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, invalid()
	}
	for _, k := range []string{"state", "code", "error"} {
		if len(q[k]) > 1 {
			return nil, invalid()
		}
	}
	if len(q["state"]) != 1 || q.Get("state") != state {
		return nil, invalid()
	}
	_, hasCode := q["code"]
	_, hasError := q["error"]
	if hasCode == hasError {
		return nil, invalid()
	}
	key := "code"
	if hasError {
		key = "error"
	}
	if q.Get(key) == "" {
		return nil, invalid()
	}
	return map[string]any{key: q.Get(key), "state": state}, nil
}
func (c *Client) call(id string, p map[string]any) (any, error) {
	op := contract["operations"].(map[string]any)[id].(map[string]any)
	var body io.Reader
	if name, ok := op["requestSchema"].(string); ok {
		obj := map[string]any{}
		for _, f := range op["fields"].([]any) {
			field := f.(map[string]any)
			wire := field["wire"].(string)
			if value, ok := field["value"]; ok {
				obj[wire] = value
			} else if wire == "client_id" {
				obj[wire] = c.id
			} else if wire == "client_secret" {
				obj[wire] = c.secret
			} else {
				obj[wire] = p[field["param"].(string)]
			}
		}
		if !validate(contract["schemas"].(map[string]any)[name].(map[string]any), obj) {
			return nil, invalid()
		}
		b, _ := json.Marshal(obj)
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequest(op["method"].(string), c.base+op["path"].(string), body)
	if e != nil {
		return nil, invalid()
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AnyOAuth-go/0.1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if op["auth"] == "bearer" {
		token := str(p, "accessToken")
		if token == "" || strings.ContainsAny(token, "\r\n") {
			return nil, invalid()
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := c.http.Do(req)
	if e != nil {
		return nil, &Error{0, "transport_error", "Request failed or timed out"}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var value any
		decoder := json.NewDecoder(res.Body)
		if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || !validate(contract["schemas"].(map[string]any)["ApiError"].(map[string]any), value) {
			return nil, &Error{res.StatusCode, "protocol_error", "Invalid error response"}
		}
		obj := value.(map[string]any)
		message := "HTTP request failed"
		if s, ok := obj["message"].(string); ok {
			message = s
		}
		return nil, &Error{res.StatusCode, obj["error"].(string), message}
	}
	if res.StatusCode != int(op["successStatus"].(float64)) {
		return nil, &Error{res.StatusCode, "protocol_error", "Unexpected response status"}
	}
	if op["responseSchema"] == nil {
		return nil, nil
	}
	var value any
	decoder := json.NewDecoder(res.Body)
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || !validate(contract["schemas"].(map[string]any)[op["responseSchema"].(string)].(map[string]any), value) {
		return nil, &Error{res.StatusCode, "protocol_error", "Invalid response"}
	}
	return value, nil
}

func (c *Client) ExchangeCode(params map[string]any) (any, error) {
	return c.call("exchangeCode", params)
}

func (c *Client) Profile(params map[string]any) (any, error) { return c.call("profile", params) }

func (c *Client) Revoke(params map[string]any) (any, error) { return c.call("revoke", params) }

func (c *Client) Providers(params map[string]any) (any, error) { return c.call("providers", params) }
