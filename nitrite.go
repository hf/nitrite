// Package nitrite implements attestation verification for AWS Nitro Enclaves.
package nitrite

import (
	"crypto/x509"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"io"
	"time"
)

// Document represents the AWS Nitro Enclave Attestation Document.
type Document struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

// Result is a successful verification result of an attestation payload.
type Result struct {
	Document *Document `json:"document,omitempty"`

	Certificates []*x509.Certificate `json:"certificates,omitempty"`

	Protected   []byte `json:"protected,omitempty"`
	Unprotected []byte `json:"unprotected,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Signature   []byte `json:"signature,omitempty"`
}

// VerifyOptions specifies the options for verifying the attestation payload.
// If `Roots` is nil, the `DefaultCARoot` is used. If `CurrentTime` is 0,
// `time.Now()` will be used. It is a strong recommendation you explicitly
// supply this value.
type VerifyOptions struct {
	Roots       *x509.CertPool
	CurrentTime time.Time
}

type coseHeader struct {
	Algorithm string `cbor:"1,keyasint,omitempty" json:"alg,omitempty"`
}

// Errors that are encountered when manipulating the COSE1Sign structure.
var (
	ErrBadCOSE1SignStructure          error = errors.New("Data is not a COSE1Sign array")
	ErrCOSE1SignEmptyProtectedSection error = errors.New("COSE1Sign protected section is nil or empty")
	ErrCOSE1SignEmptyPayloadSection   error = errors.New("COSE1Sign payload section is nil or empty")
	ErrCOSE1SignEmptySignatureSection error = errors.New("COSE1Sign signature section is nil or empty")
	ErrCOSE1SignBadAlgorithm          error = errors.New("COSE1Sign algorithm not ECDSA384")
)

// Errors encountered when parsing the CBOR attestation document.
var (
	ErrBadAttestationDocument           error = errors.New("Bad attestation document")
	ErrMandatoryFieldsMissing           error = errors.New("One or more of mandatory fields missing")
	ErrBadDigest                        error = errors.New("Payload 'digest' is not SHA384")
	ErrBadTimestamp                     error = errors.New("Payload 'timestamp' is 0 or less")
	ErrBadPCRs                          error = errors.New("Payload 'pcrs' is less than 1 or more than 32")
	ErrBadPCRIndex                      error = errors.New("Payload 'pcrs' key index is not in [0, 32)")
	ErrBadPCRValue                      error = errors.New("Payload 'pcrs' value is nil or not of length {32,48,64}")
	ErrBadCABundle                      error = errors.New("Payload 'cabundle' has 0 elements")
	ErrBadCABundleItem                  error = errors.New("Payload 'cabundle' has a nil item or of length not in [1, 1024]")
	ErrBadPublicKey                     error = errors.New("Payload 'public_key' has a value of length not in [1, 1024]")
	ErrBadUserData                      error = errors.New("Payload 'user_data' has a value of length not in [1, 512]")
	ErrBadNonce                         error = errors.New("Payload 'nonce' has a value of length not in [1, 512]")
	ErrBadCertificatePublicKeyAlgorithm error = errors.New("Payload 'certificate' has a bad public key algorithm (not ECDSA)")
	ErrBadCertificateSigningAlgorithm   error = errors.New("Payload 'certificate' has a bad public key signing algorithm (not ECDSAWithSHA384)")
)

const (
	// DefaultCARoots contains the PEM encoded roots for verifying Nitro
	// Enclave attestation signatures. You can download them from
	// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	// It's recommended you calculate the SHA256 sum of this string and match
	// it to the one supplied in the AWS documentation
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	DefaultCARoots string = "-----BEGIN CERTIFICATE-----\nMIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\nMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\nVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\nMTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\nDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\nBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\nh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\nR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\nMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\nrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\nIwLz3/Y=\n-----END CERTIFICATE----\n"
)

var (
	defaultRoot *x509.CertPool = createAWSNitroRoot()
)

func createAWSNitroRoot() *x509.CertPool {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM([]byte(DefaultCARoots))
	if !ok {
		return nil
	}

	return pool
}

// Verify verifies the attestation payload from `data` with the provided
// verification options. If the options specify `Roots` as `nil`, the
// `DefaultCARoot` will be used. If you do not specify `CurrentTime`,
// `time.Now()` will be used. It is strongly recommended you specifically
// supply the time.  If the returned error is non-nil, it is either one of the
// `Err` codes specified in this package, or is an error from the `crypto/x509`
// package.
func Verify(data io.Reader, options VerifyOptions) (*Result, error) {
	cose1 := make([][]byte, 0, 4)

	decoder := cbor.NewDecoder(data)
	err := decoder.Decode(&cose1)
	if nil != err {
		return nil, ErrBadCOSE1SignStructure
	}

	if nil == cose1 || 4 != len(cose1) {
		return nil, ErrBadCOSE1SignStructure
	}

	if nil == cose1[0] || 0 == len(cose1[0]) {
		return nil, ErrCOSE1SignEmptyProtectedSection
	}

	if nil == cose1[2] || 0 == len(cose1[2]) {
		return nil, ErrCOSE1SignEmptyPayloadSection
	}

	if nil == cose1[3] || 0 == len(cose1[3]) {
		return nil, ErrCOSE1SignEmptySignatureSection
	}

	header := coseHeader{}
	err = cbor.Unmarshal(cose1[0], &header)
	if nil != err {
		return nil, ErrBadCOSE1SignStructure
	}

	if "ECDSA384" != header.Algorithm {
		return nil, ErrCOSE1SignBadAlgorithm
	}

	doc := Document{}

	err = cbor.Unmarshal(cose1[2], &doc)
	if nil != err {
		return nil, ErrBadAttestationDocument
	}

	if "" == doc.ModuleID || "" == doc.Digest || 0 == doc.Timestamp || nil == doc.PCRs || nil == doc.Certificate || nil == doc.CABundle {
		return nil, ErrMandatoryFieldsMissing
	}

	if "SHA384" != doc.Digest {
		return nil, ErrBadDigest
	}

	if doc.Timestamp < 1 {
		return nil, ErrBadTimestamp
	}

	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return nil, ErrBadPCRs
	}

	for key, value := range doc.PCRs {
		if key < 0 || key > 31 {
			return nil, ErrBadPCRIndex
		}

		if nil == value || 32 != len(value) || 48 != len(value) || 64 != len(value) {
			return nil, ErrBadPCRValue
		}
	}

	if len(doc.CABundle) < 1 {
		return nil, ErrBadCABundle
	}

	for _, item := range doc.CABundle {
		if nil == item || len(item) < 1 || len(item) > 1024 {
			return nil, ErrBadCABundleItem
		}
	}

	if nil != doc.PublicKey && (len(doc.PublicKey) < 1 || len(doc.PublicKey) > 1024) {
		return nil, ErrBadPublicKey
	}

	if nil != doc.UserData && (len(doc.UserData) < 1 || len(doc.UserData) > 512) {
		return nil, ErrBadUserData
	}

	if nil != doc.Nonce && (len(doc.Nonce) < 1 || len(doc.Nonce) > 512) {
		return nil, ErrBadNonce
	}

	certificates := make([]*x509.Certificate, 0, len(doc.CABundle)+1)

	cert, err := x509.ParseCertificate(doc.Certificate)
	if nil != err {
		return nil, err
	}

	if x509.ECDSA != cert.PublicKeyAlgorithm {
		return nil, ErrBadCertificatePublicKeyAlgorithm
	}

	if x509.ECDSAWithSHA384 != cert.SignatureAlgorithm {
		return nil, ErrBadCertificateSigningAlgorithm
	}

	certificates = append(certificates, cert)

	intermediates := x509.NewCertPool()

	for _, item := range doc.CABundle {
		cert, err := x509.ParseCertificate(item)
		if nil != err {
			return nil, err
		}

		intermediates.AddCert(cert)
		certificates = append(certificates, cert)
	}

	roots := options.Roots
	if nil == roots {
		roots = defaultRoot
	}

	currentTime := options.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	})
	if nil != err {
		return nil, err
	}

	return &Result{
		Document:     &doc,
		Certificates: certificates,
		Protected:    cose1[0],
		Unprotected:  cose1[1],
		Payload:      cose1[2],
		Signature:    cose1[3],
	}, nil
}
