// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package requester

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestN(t *testing.T) {
	var count int64
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, int64(1))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	w := &Work{
		Request: req,
		N:       20,
		C:       2,
	}
	w.Run()
	if count != 20 {
		t.Errorf("Expected to send 20 requests, found %v", count)
	}
}

func TestQps(t *testing.T) {
	var wg sync.WaitGroup
	var count int64
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, int64(1))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	w := &Work{
		Request: req,
		N:       20,
		C:       2,
		QPS:     1,
	}
	wg.Add(1)
	time.AfterFunc(time.Second, func() {
		if count > 2 {
			t.Errorf("Expected to work at most 2 times, found %v", count)
		}
		wg.Done()
	})
	go w.Run()
	wg.Wait()
}

func TestRequest(t *testing.T) {
	var uri, contentType, some, auth string
	handler := func(w http.ResponseWriter, r *http.Request) {
		uri = r.RequestURI
		contentType = r.Header.Get("Content-type")
		some = r.Header.Get("X-some")
		auth = r.Header.Get("Authorization")
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	header := make(http.Header)
	header.Add("Content-type", "text/html")
	header.Add("X-some", "value")
	req, _ := http.NewRequest("GET", server.URL, nil)
	req.Header = header
	req.SetBasicAuth("username", "password")
	w := &Work{
		Request: req,
		N:       1,
		C:       1,
	}
	w.Run()
	if uri != "/" {
		t.Errorf("Uri is expected to be /, %v is found", uri)
	}
	if contentType != "text/html" {
		t.Errorf("Content type is expected to be text/html, %v is found", contentType)
	}
	if some != "value" {
		t.Errorf("X-some header is expected to be value, %v is found", some)
	}
	if auth != "Basic dXNlcm5hbWU6cGFzc3dvcmQ=" {
		t.Errorf("Basic authorization is not properly set")
	}
}

func TestBody(t *testing.T) {
	var count int64
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) == "Body" {
			atomic.AddInt64(&count, 1)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBuffer([]byte("Body")))
	w := &Work{
		Request:     req,
		RequestBody: []byte("Body"),
		N:           10,
		C:           1,
	}
	w.Run()
	if count != 10 {
		t.Errorf("Expected to work 10 times, found %v", count)
	}
}

func TestTLSWithCACert(t *testing.T) {
	// Create temp directory for certs
	tempDir, err := ioutil.TempDir("", "hey-test-certs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate CA certificate
	caCert, caKey, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate server certificate
	serverCert, serverKey, err := generateTestCert(caCert, caKey, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Write CA cert to file
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caCertPEM := certToPEM(caCert)
	if err := ioutil.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	// Create TLS server
	serverTLSCert, err := tls.X509KeyPair(certToPEM(serverCert), keyToPEM(serverKey))
	if err != nil {
		t.Fatalf("Failed to create server TLS cert: %v", err)
	}

	var count int64
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, int64(1))
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server.StartTLS()
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	w := &Work{
		Request: req,
		N:       5,
		C:       1,
		CACert:  caCertPath,
	}
	w.Run()
	if count != 5 {
		t.Errorf("Expected to send 5 requests, found %v", count)
	}
}

func TestTLSWithClientCert(t *testing.T) {
	// Create temp directory for certs
	tempDir, err := ioutil.TempDir("", "hey-test-certs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate CA certificate
	caCert, caKey, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate server certificate
	serverCert, serverKey, err := generateTestCert(caCert, caKey, "localhost")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Generate client certificate
	clientCert, clientKey, err := generateTestCert(caCert, caKey, "client")
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	// Write certs to files
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caCertPEM := certToPEM(caCert)
	if err := ioutil.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	clientCertPath := filepath.Join(tempDir, "client.crt")
	if err := ioutil.WriteFile(clientCertPath, certToPEM(clientCert), 0644); err != nil {
		t.Fatalf("Failed to write client cert: %v", err)
	}

	clientKeyPath := filepath.Join(tempDir, "client.key")
	if err := ioutil.WriteFile(clientKeyPath, keyToPEM(clientKey), 0600); err != nil {
		t.Fatalf("Failed to write client key: %v", err)
	}

	// Create TLS server with client authentication
	serverTLSCert, err := tls.X509KeyPair(certToPEM(serverCert), keyToPEM(serverKey))
	if err != nil {
		t.Fatalf("Failed to create server TLS cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	var count int64
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, int64(1))
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	w := &Work{
		Request: req,
		N:       5,
		C:       1,
		CACert:  caCertPath,
		Cert:    clientCertPath,
		Key:     clientKeyPath,
	}
	w.Run()
	if count != 5 {
		t.Errorf("Expected to send 5 requests, found %v", count)
	}
}

// Helper functions for generating test certificates

func generateTestCA() (*x509.Certificate, interface{}, error) {
	return generateTestCertInternal(nil, nil, "TestCA", true)
}

func generateTestCert(caCert *x509.Certificate, caKey interface{}, commonName string) (*x509.Certificate, interface{}, error) {
	return generateTestCertInternal(caCert, caKey, commonName, false)
}

func generateTestCertInternal(caCert *x509.Certificate, caKey interface{}, commonName string, isCA bool) (*x509.Certificate, interface{}, error) {
	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	parent := template
	parentKey := key
	if caCert != nil && caKey != nil {
		parent = caCert
		parentKey = caKey.(*rsa.PrivateKey)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyToPEM(key interface{}) []byte {
	rsaKey := key.(*rsa.PrivateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
}

func TestResolve(t *testing.T) {
	var count int64
	var receivedHost string
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, int64(1))
		receivedHost = r.Host
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	// Extract port from the test server URL
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())

	// Create a request with a fake hostname
	fakeHost := "fake.example.com:" + port
	req, _ := http.NewRequest("GET", "http://"+fakeHost+"/", nil)

	w := &Work{
		Request: req,
		N:       5,
		C:       1,
		Resolve: "fake.example.com:" + port + ":127.0.0.1",
	}
	w.Run()

	if count != 5 {
		t.Errorf("Expected to send 5 requests, found %v", count)
	}
	if receivedHost != fakeHost {
		t.Errorf("Expected Host header to be %s, got %s", fakeHost, receivedHost)
	}
}
