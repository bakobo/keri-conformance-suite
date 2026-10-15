package main

import "os"

// exit is os.Exit, a variable so a test can run main.
var exit = os.Exit

func main() {
	exit(serve(os.Stdin, os.Stdout, os.Stderr, maxRequestLine))
}
