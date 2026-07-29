package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {
	var header http.Header
	var errMalformed = errors.New("malformed authorization header")

	// Test: Good Header
	header = http.Header{}
	header.Add("Authorization", "ApiKey 123456")
	key, err := GetAPIKey(header)
	require.NoError(t, err)
	assert.Equal(t, "123456", key)

	// Test: No Header
	header = http.Header{}
	_, err = GetAPIKey(header)
	require.Error(t, err)
	assert.Equal(t, ErrNoAuthHeaderIncluded, err)

	// Test: Missing Key
	header = http.Header{}
	header.Add("Authorization", "Bearer 123456")
	_, err = GetAPIKey(header)
	require.Error(t, err)
	assert.Equal(t, errMalformed, err)

	// Test: Malformed
	header = http.Header{}
	header.Add("Authorization", "ApiKey")
	_, err = GetAPIKey(header)
	require.Error(t, err)
	assert.Equal(t, errMalformed, err)
}
