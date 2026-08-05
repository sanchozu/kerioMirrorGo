package main

import "testing"

func TestServerAddressFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "defaults to all interfaces and port 8080",
			env:  map[string]string{},
			want: "0.0.0.0:8080",
		},
		{
			name: "uses HOST before IP",
			env: map[string]string{
				"HOST": "127.0.0.1",
				"IP":   "10.0.0.10",
				"PORT": "9090",
			},
			want: "127.0.0.1:9090",
		},
		{
			name: "uses IP when HOST is empty",
			env: map[string]string{
				"IP":   "10.0.0.10",
				"PORT": "8181",
			},
			want: "10.0.0.10:8181",
		},
		{
			name: "uses default port with custom host",
			env: map[string]string{
				"HOST": "localhost",
			},
			want: "localhost:8080",
		},
		{
			name: "brackets IPv6 hosts",
			env: map[string]string{
				"HOST": "::1",
				"PORT": "8088",
			},
			want: "[::1]:8088",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOST", "")
			t.Setenv("IP", "")
			t.Setenv("PORT", "")
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			if got := serverAddressFromEnv(); got != tt.want {
				t.Fatalf("serverAddressFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTLSServerAddressFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "defaults to all interfaces and port 443",
			env:  map[string]string{},
			want: "0.0.0.0:443",
		},
		{
			name: "uses TLS_PORT",
			env: map[string]string{
				"TLS_PORT": "8443",
			},
			want: "0.0.0.0:8443",
		},
		{
			name: "falls back to HTTPS_PORT",
			env: map[string]string{
				"HTTPS_PORT": "9443",
			},
			want: "0.0.0.0:9443",
		},
		{
			name: "uses host from HOST",
			env: map[string]string{
				"HOST":     "127.0.0.1",
				"TLS_PORT": "8443",
			},
			want: "127.0.0.1:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOST", "")
			t.Setenv("IP", "")
			t.Setenv("TLS_PORT", "")
			t.Setenv("HTTPS_PORT", "")
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			if got := tlsServerAddressFromEnv(); got != tt.want {
				t.Fatalf("tlsServerAddressFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}
