package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(downloadSigningKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expires <= now.Unix() {
		return false
	}
	// Solution
	providedSignatureDecoded, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	expectedHMAC := signDownload(downloadSigningKey, fileID, expires)
	expectedSignatureDecoded, err := hex.DecodeString(expectedHMAC)
	if err != nil {
		return false
	}

	return 1 == subtle.ConstantTimeCompare(expectedSignatureDecoded, providedSignatureDecoded)
}

func signDownload(signingKey [32]byte, fileID, expires int64) string {
	// example of signed URL: http://localhost:3030/files/1/signed-download?expires=1300&signature=15a4b83da8db92f7d83ac2684ebe7d1a98108b165d4d18fbae94098ae291e5f2
	mac := hmac.New(sha256.New, signingKey[:]) // signature will become a 64-characted hexadecimal MAC over the method, path and timestamp
	// Signed URL contains resource path, expiration timestamp and a signature
	payload := fmt.Sprintf("GET\n/files/%d/signed-download\n%d", fileID, expires)
	// payload example:
	// GET
	///files/1/signed-download
	//1762300300
	mac.Write([]byte(payload))
	// That payload plus the 32-byte signing key goes through HMAC-SHA-256, producing 32 raw bytes, which hex.EncodeToString turns into 64 lowercase hex characters. The result:
	// /files/1/signed-download?expires=1762300300&signature=15a4b83da8db92f7d83ac2684ebe7d1a98108b165d4d18fbae94098ae291e5f2
	expectedMAC := mac.Sum(nil)
	return hex.EncodeToString(expectedMAC)
}
