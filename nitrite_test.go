package nitrite_test

import (
	"errors"
	"strings"
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
		t.Fatalf("not equal: want %v, got %v", want, got)
	}
}

func requireErrorIs(t *testing.T, got, want error) {
	if !errors.Is(got, want) {
		t.Fatalf("unexpected error type: want %T, got %T", want, got)
	}
}

func requireErrorContains(t *testing.T, err error, substr string) {
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

func TestAttestationCreatedAt(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		wantTime := time.Now()
		doc := nitrite.Document{
			Timestamp: uint64(wantTime.UnixMilli()),
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
		requireEqual(t, gotTime.UnixMilli(), wantTime.UnixMilli())
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
		requireErrorContains(t, err, "no timestamp")
	})
}
