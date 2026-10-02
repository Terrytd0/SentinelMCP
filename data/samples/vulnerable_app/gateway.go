// Deliberately vulnerable sample code, for exercising the real Semgrep scanner.
//
// The Python half of this sample is `app.py`. This file exists because two of
// the seven rewrites in `backend/agents/deterministic.py` -- `disable-tls-
// verification` and `math-rand-to-crypto-rand` -- match Go patterns and nothing
// else, so without it they had no target in this repository and could not be
// measured by either evidence tier. See docs/evidence.md.
//
// Every construct here maps to a CWE the remediation engine has a rewrite for.
// Do not "fix" these -- that is the whole point of the file. In particular, note
// that `secrets.randbelow` is a *Python* name: the rewrite for `math-rand` emits
// it here, where Go's secure equivalent is `crypto/rand`, so the patch does not
// compile. That is a finding, and it is recorded in docs/evidence.md.
package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const StripeSecretKey = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY" // CWE-798

// newGatewayClient disables certificate verification. CWE-295.
func newGatewayClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // deliberate
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// makeReference produces a predictable settlement reference. CWE-338.
//
// A predictable transaction reference is a business-logic vulnerability even
// though the value is not itself a secret, which is why the rewrite's
// description says so.
func makeReference() string {
	return fmt.Sprintf("ord_%d", rand.Intn(1000000))
}

func main() {
	client := newGatewayClient()
	_ = client
	fmt.Fprintln(os.Stdout, makeReference())
}
