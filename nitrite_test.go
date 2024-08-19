package nitrite_test

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationCreatedAt(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		wantTime := time.Now()
		doc := nitrite.Document{
			Timestamp: uint64(wantTime.UnixMilli()),
		}
		docBytes, err := cbor.Marshal(doc)
		require.NoError(t, err)
		cosePayload := nitrite.CosePayload{
			Payload: docBytes,
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		require.NoError(t, err)

		// when
		gotTime, err := nitrite.Timestamp(cosePayloadBytes)

		// then
		require.NoError(t, err)
		assert.Equal(t, wantTime.UnixMilli(), gotTime.UnixMilli())
	})

	t.Run("cannot unmarshal COSE payload", func(t *testing.T) {
		// when
		_, err := nitrite.Timestamp([]byte("invalid"))

		// then
		assert.ErrorIs(t, err, nitrite.ErrBadCOSESign1Structure)
	})

	t.Run("cannot unmarshal Document", func(t *testing.T) {
		// given
		cosePayload := nitrite.CosePayload{
			Payload: []byte("invalid"),
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		require.NoError(t, err)

		// when
		_, err = nitrite.Timestamp(cosePayloadBytes)

		// then
		assert.ErrorIs(t, err, nitrite.ErrBadAttestationDocument)
	})

	t.Run("attestation document has no timestamp", func(t *testing.T) {
		// given
		doc := nitrite.Document{
			Timestamp: 0,
		}
		docBytes, err := cbor.Marshal(doc)
		require.NoError(t, err)
		cosePayload := nitrite.CosePayload{
			Payload: docBytes,
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		require.NoError(t, err)

		// when
		_, err = nitrite.Timestamp(cosePayloadBytes)

		// then
		assert.ErrorIs(t, err, nitrite.ErrMandatoryFieldsMissing)
		assert.ErrorContains(t, err, "no timestamp")
	})
}
