package main

import (
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
)

func main() {
	var mockType string
	flag.StringVar(&mockType, "mock", "pve", "pve or post_creation")
	flag.Parse()

	r := gin.Default()
	// make gin happy
	r.SetTrustedProxies([]string{})

	switch mockType {
	case "pve":
		panic(mockPveServer(r))
	case "post_creation":
		panic(mockPostCreationServer(r))
	default:
		panic(fmt.Sprintf("unknown mock type: %s", mockType))
	}
}
