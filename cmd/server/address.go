package main

import (
	"net"
	"os"
)

func serverAddressFromEnv() string {
	host := os.Getenv("HOST")
	if host == "" {
		host = os.Getenv("IP")
	}
	if host == "" {
		host = "0.0.0.0"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return net.JoinHostPort(host, port)
}
