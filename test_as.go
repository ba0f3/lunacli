package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
)

func main() {
    uErr := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("inner error")}

    var netErr net.Error
    fmt.Println(errors.As(uErr, &netErr))

    var t interface{ Unwrap() error }
    fmt.Println(errors.As(uErr, &t))
}
