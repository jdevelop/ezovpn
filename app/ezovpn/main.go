package main

import (
	"log"

	"github.com/jdevelop/ezovpn/app/ezovpn/cmds"
)

func main() {
	if err := cmds.Execute(); err != nil {
		log.Fatal(err)
	}
}
