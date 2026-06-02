package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var (
	errFakeFailedRetrieveToken = errors.New("failed to retrieve token")
	testSigningKey             = []byte("test-signing-key-unit-test-only")
)

type testTokenCredential struct {
	Subject       string
	Error         error
	LastScopes    []string
	LastEnableCAE bool
}

func (t *testTokenCredential) GetToken(
	ctx context.Context,
	opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	t.LastScopes = opts.Scopes
	t.LastEnableCAE = opts.EnableCAE

	if t.Error != nil {
		return azcore.AccessToken{}, t.Error
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": t.Subject,
	})

	tokenStr, err := token.SignedString(testSigningKey)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{Token: tokenStr, ExpiresOn: time.Now().Add(24 * time.Hour)}, nil
}

func TestGetOAuthTokenSuccess(t *testing.T) {
	testCases := map[string]struct {
		saslAlgorithm        string
		opts                 OAuthProviderOpts
		expectedSubject      string
		expectedExpiredAfter time.Time
		expectedRefreshAfter time.Time
	}{
		"azure entra": {
			saslAlgorithm: saslAzureEntra,
			opts: OAuthProviderOpts{
				azureTokenCredential: &testTokenCredential{
					Subject: "test-sub",
				},
			},
			expectedSubject:      "test-sub",
			expectedExpiredAfter: time.Now(),
			expectedRefreshAfter: time.Time{},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			provider, err := NewOAuthProvider(test.saslAlgorithm, []string{"broker1:9093"}, test.opts)
			require.NoError(t, err)

			token, err := provider.GetToken(t.Context())

			require.NoError(t, err)
			require.NotEmpty(t, token.Token)
			require.Equal(t, test.expectedSubject, token.Subject)
			require.GreaterOrEqual(t, token.ExpiresOn, test.expectedExpiredAfter)
			require.GreaterOrEqual(t, token.RefreshOn, test.expectedRefreshAfter)
		})
	}
}

func TestGetOAuthTokenFailure(t *testing.T) {
	testCases := map[string]struct {
		saslAlgorithm string
		opts          OAuthProviderOpts
	}{
		"azure entra": {
			saslAlgorithm: saslAzureEntra,
			opts: OAuthProviderOpts{
				azureTokenCredential: &testTokenCredential{
					Error: errFakeFailedRetrieveToken,
				},
			},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			provider, err := NewOAuthProvider(test.saslAlgorithm, []string{"broker1:9093"}, test.opts)
			require.NoError(t, err)

			_, err = provider.GetToken(t.Context())

			var xk6KafkaError *Xk6KafkaError
			ok := errors.As(err, &xk6KafkaError)

			require.True(t, ok, "error is not Xk6KafkaError")
			require.Equal(t, failedGetOAuthToken, xk6KafkaError.Code)
		})
	}
}

func TestUnsupportedOAuthProvider(t *testing.T) {
	_, err := NewOAuthProvider(saslPlain, []string{"broker1"}, OAuthProviderOpts{})
	require.ErrorContains(t, err, "sasl_plain is not a supported OAuth Provider.")
}

// TestAzureEntraScopeOverride verifies that the SASLConfig.Scope field
// overrides the auto-derived "https://<broker-host>/.default" scope.
// Self-hosted Kafka brokers using Entra ID via an app registration need
// the override; Event Hubs deployments still rely on auto-derivation.
func TestAzureEntraScopeOverride(t *testing.T) {
	const overrideScope = "api://00000000-0000-0000-0000-000000000000/.default"

	testCases := map[string]struct {
		saslConfig     SASLConfig
		brokers        []string
		expectedScopes []string
	}{
		"explicit scope overrides auto-derivation": {
			saslConfig: SASLConfig{
				Algorithm: saslAzureEntra,
				Scope:     overrideScope,
			},
			brokers:        []string{"broker.example.invalid:9093"},
			expectedScopes: []string{overrideScope},
		},
		"empty scope falls back to host-derived default": {
			saslConfig: SASLConfig{
				Algorithm: saslAzureEntra,
			},
			brokers:        []string{"ns.servicebus.windows.net:9093"},
			expectedScopes: []string{"https://ns.servicebus.windows.net/.default"},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			cred := &testTokenCredential{Subject: "test-sub"}
			ctx, err := NewSaslContext(test.saslConfig, test.brokers, SASLContextOpts{
				OAuthProviderOpts: OAuthProviderOpts{azureTokenCredential: cred},
			})
			require.NoError(t, err)
			require.NotNil(t, ctx.OAuthProvider, "OAuthProvider should be set for sasl_azure_entra")

			_, err = (*ctx.OAuthProvider).GetToken(t.Context())
			require.NoError(t, err)
			require.Equal(t, test.expectedScopes, cred.LastScopes)
		})
	}
}
