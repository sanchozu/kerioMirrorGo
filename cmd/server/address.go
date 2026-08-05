package main

import (
	"net"
	"os"
)

func serverHostFromEnv() string {
	host := os.Getenv("HOST")
	if host == "" {
		host = os.Getenv("IP")
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host
}

func serverAddressFromEnv() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return net.JoinHostPort(serverHostFromEnv(), port)
}

func tlsServerAddressFromEnv() string {
	port := os.Getenv("TLS_PORT")
	if port == "" {
		port = os.Getenv("HTTPS_PORT")
	}
	if port == "" {
		port = "443"
	}

	return net.JoinHostPort(serverHostFromEnv(), port)
}
