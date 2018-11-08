package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	mr "math/rand"
	"net/http"
	"time"
)

type validityDate struct {
	Years  int `json:"years"`
	Months int `json:"months"`
	Days   int `json:"days"`
}

type certRequest struct {
	CommonName   string       `json:"cn"`
	DNSNames     []string     `json:"dns_names"`
	ValidityDate validityDate `json:"validity"`
}

type certResponse struct {
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Certificate string `json:"certificate"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", fmt.Sprintf("%s,%s", http.MethodGet, http.MethodHead))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(204)
	})

	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			generateCert(w, r)
			return
		}
	})

	log.Fatal(http.ListenAndServe(":9777", mux))
}

func generateCert(w http.ResponseWriter, r *http.Request) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	request := &certRequest{}
	if err := json.Unmarshal(buf.Bytes(), request); err != nil {
		log.Printf("Parse error: %s\n", err)
	}

	// Default to 1 Year if validity is not passed
	vyears := request.ValidityDate.Years
	vmonths := request.ValidityDate.Months
	vdays := request.ValidityDate.Days
	if vyears+vmonths+vdays == 0 {
		vyears = 1
	}
	notAfter := time.Now().AddDate(vyears, vmonths, vdays)

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: request.CommonName},
		DNSNames:     request.DNSNames,
		SerialNumber: generateSerial(16),
		NotBefore:    time.Now(),
		NotAfter:     notAfter,
	}

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("privateKey err: %s\n", err)
	}

	publickey := &privatekey.PublicKey
	parent := template

	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, privatekey)
	if err != nil {
		fmt.Printf("createCert err: %s\n", err)
	}

	pubkey, _ := x509.MarshalPKIXPublicKey(publickey)

	res := certResponse{
		PrivateKey:  base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privatekey)),
		PublicKey:   base64.StdEncoding.EncodeToString(pubkey),
		Certificate: base64.StdEncoding.EncodeToString(cert),
	}

	j, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func generateSerial(l int) *big.Int {
	seed := "0123456789"
	buf := make([]byte, l)
	for i := 0; i < l; i++ {
		buf[i] = seed[mr.Intn(len(seed))]
	}

	z := new(big.Int)
	z.SetBytes(buf)
	return z
}
