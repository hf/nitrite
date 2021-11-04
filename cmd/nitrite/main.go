package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hf/nitrite"
	"os"
	"time"
)

var (
	fDocument = flag.String("attestation", "", "Attestation document in standard Base64 encoding")
)

func main() {
	flag.Parse()

	if "" == *fDocument {
		flag.PrintDefaults()
		os.Exit(1)
	}

	document, err := base64.StdEncoding.DecodeString(*fDocument)
	if nil != err {
		fmt.Printf("Provided attestation document is not encoded as a valid standard Base64 string\n")
		os.Exit(2)
	}

	res, err := nitrite.Verify(
		document,
		nitrite.VerifyOptions{
			CurrentTime: time.Now(),
		},
	)

	resJSON := ""

	if nil != res {
		enc, err := json.Marshal(res.Document)
		if nil != err {
			panic(err)
		}

		resJSON = string(enc)
	}

	if nil != err {
		fmt.Printf("Attestation verification failed with error %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("%v\n", resJSON)
}
