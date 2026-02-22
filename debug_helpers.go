package main

import (
	"log"
	"runtime/debug"
)

func logErrorWithTrace(msg string, err error) {
	if err == nil {
		return
	}
	log.Printf("%s: %v", msg, err)
	debug.PrintStack()
}
