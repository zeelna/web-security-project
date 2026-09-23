package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
	//"crypto/subtle"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(jsonPayload any, providedKey, expectedKey []byte) WebhookVerification {
	if subtle.ConstantTimeCompare(providedKey, expectedKey) != 1 { // 1 is 'equal' in lib 'crypto/subtle'
		return WebhookVerification{
			Outcome: WebhookUnauthorized,
		}
	}

	payloadRecord, ok := jsonPayload.(map[string]any)
	if !ok {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	orderID, ok := payloadRecord["orderId"].(float64)            // 'encoding/json' always returns float64 for numbers. Therefore, cannot cast into .(int64), would produce !ok
	if !ok || orderID <= 0.0 || orderID != math.Trunc(orderID) { // math.Trunc() removes fractional part
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
