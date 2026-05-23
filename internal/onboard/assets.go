package onboard

import _ "embed"

//go:generate go run gen_bundle.go

//go:embed bundle.tar.gz
var embeddedBundle []byte
