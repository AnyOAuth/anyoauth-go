package main

import (
	"encoding/json"
	sdk "github.com/AnyOAuth/anyoauth-go"
	"os"
)

func main() {
	var input struct {
		Action       string
		BaseURL      string
		ClientID     string
		ClientSecret string
		Params       map[string]any
	}
	var result any
	var err error
	if json.NewDecoder(os.Stdin).Decode(&input) != nil {
		err = &sdk.Error{Status: 0, Code: "invalid_argument", Message: "Invalid input"}
	} else {
		var c *sdk.Client
		c, err = sdk.NewClient(input.BaseURL, input.ClientID, input.ClientSecret)
		if err == nil {
			p := input.Params
			switch input.Action {
			case "exchangeCode":
				result, err = c.ExchangeCode(p)
			case "profile":
				result, err = c.Profile(p)
			case "revoke":
				result, err = c.Revoke(p)
			case "providers":
				result, err = c.Providers(p)
			case "pkceChallenge":
				v, _ := p["codeVerifier"].(string)
				result, err = sdk.PKCEChallenge(v)
			case "createTransaction":
				result, err = sdk.CreateTransaction()
			case "authorizationUrl":
				result, err = c.AuthorizationURL(p)
			case "validateCallback":
				result, err = sdk.ValidateCallback(p)
			default:
				err = &sdk.Error{Status: 0, Code: "invalid_argument", Message: "Unknown action"}
			}
		}
	}
	out := map[string]any{"ok": true, "result": result}
	if err != nil {
		e, ok := err.(*sdk.Error)
		if !ok {
			e = &sdk.Error{Status: 0, Code: "internal_error", Message: "Operation failed"}
		}
		out = map[string]any{"ok": false, "error": e}
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
