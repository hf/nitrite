package nitrite_test

import (
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

func requireNoError(t *testing.T, got error) {
	if got != nil {
		t.Fatalf("unexpected error: %v", got)
	}
}

func requireEqual(t *testing.T, got, want interface{}) {
	if got != want {
		t.Fatalf("not equal: got %v, want %v", got, want)
	}
}

func requireErrorIs(t *testing.T, got, want error) {
	if !errors.Is(got, want) {
		t.Fatalf("unexpected error type: got %T, want %T", got, want)
	}
}

func TestAttestationCreatedAt(t *testing.T) {
	timeToMillis := func(t time.Time) uint64 {
		return uint64(t.UnixNano() / 1e6)
	}

	t.Run("happy path", func(t *testing.T) {
		// given
		wantTime := time.Now()
		doc := nitrite.Document{
			Timestamp: timeToMillis(wantTime),
		}
		docBytes, err := cbor.Marshal(doc)
		requireNoError(t, err)
		cosePayload := nitrite.CosePayload{
			Payload: docBytes,
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		requireNoError(t, err)

		// when
		gotTime, err := nitrite.Timestamp(cosePayloadBytes)

		// then
		requireNoError(t, err)
		requireEqual(t, timeToMillis(gotTime), timeToMillis(wantTime))
	})

	t.Run("cannot unmarshal COSE payload", func(t *testing.T) {
		// when
		_, err := nitrite.Timestamp([]byte("invalid"))

		// then
		requireErrorIs(t, err, nitrite.ErrBadCOSESign1Structure)
	})

	t.Run("cannot unmarshal Document", func(t *testing.T) {
		// given
		cosePayload := nitrite.CosePayload{
			Payload: []byte("invalid"),
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		requireNoError(t, err)

		// when
		_, err = nitrite.Timestamp(cosePayloadBytes)

		// then
		requireErrorIs(t, err, nitrite.ErrBadAttestationDocument)
	})

	t.Run("attestation document has no timestamp", func(t *testing.T) {
		// given
		doc := nitrite.Document{
			Timestamp: 0,
		}
		docBytes, err := cbor.Marshal(doc)
		requireNoError(t, err)
		cosePayload := nitrite.CosePayload{
			Payload: docBytes,
		}
		cosePayloadBytes, err := cbor.Marshal(cosePayload)
		requireNoError(t, err)

		// when
		_, err = nitrite.Timestamp(cosePayloadBytes)

		// then
		requireErrorIs(t, err, nitrite.ErrMandatoryFieldsMissing)
	})
}
