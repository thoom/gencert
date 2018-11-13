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
	"strings"
	"time"
)

type validityDate struct {
	Years  int `json:"years"`
	Months int `json:"months"`
	Days   int `json:"days"`
}

type certRequest struct {
	CommonName string       `json:"cn"`
	DNSNames   []string     `json:"dns_names"`
	NotAfter   validityDate `json:"not_after"`
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

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: request.CommonName},
		DNSNames:     request.DNSNames,
		SerialNumber: generateSerial(16),
		NotBefore:    computeDate(nil, 0),
		NotAfter:     computeDate(&request.NotAfter, 1),
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

	base64Private := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", chunkString(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privatekey)), 64))

	pubkey, _ := x509.MarshalPKIXPublicKey(publickey)
	base64Public := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", chunkString(base64.StdEncoding.EncodeToString(pubkey), 64))

	base64Cert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", chunkString(base64.StdEncoding.EncodeToString(cert), 64))

	res := certResponse{
		PrivateKey:  base64Private,
		PublicKey:   base64Public,
		Certificate: base64Cert,
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		j, _ := json.Marshal(res)
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
	} else {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(fmt.Sprintf("%s\n%s\n%s", base64Public, base64Private, base64Cert)))
	}
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

func computeDate(vd *validityDate, defaultYears int) time.Time {
	if vd == nil {
		return time.Now()
	}

	vyears := vd.Years
	vmonths := vd.Months
	vdays := vd.Days
	if vyears+vmonths+vdays == 0 {
		vyears = defaultYears
	}

	return time.Now().AddDate(vyears, vmonths, vdays)
}

func chunkString(s string, chunkSize int) string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return s
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}

	return strings.Join(chunks, "\n")
}
