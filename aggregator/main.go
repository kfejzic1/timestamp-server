package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

type AggregatorState struct {
	mu          sync.Mutex
	config      *frost.Configuration
	ciphersuite frost.Ciphersuite
	vk          *ecc.Element
	configured  bool
}

var agg = &AggregatorState{
	ciphersuite: frost.Ristretto255,
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/config", handleConfig)
	mux.HandleFunc("/aggregate", handleAggregate)
	mux.HandleFunc("/verify", handleVerify)

	tlsConfig, err := buildTLSConfig()
	if err != nil {
		log.Printf("WARNING: mTLS not configured, running plain HTTP: %v", err)
		log.Printf("Aggregator listening on :%s (HTTP)", port)
		log.Fatal(http.ListenAndServe(":"+port, mux))
		return
	}

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Aggregator listening on :%s (mTLS)", port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("/certs/aggregator.crt", "/certs/aggregator.key")
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}

	caCert, err := os.ReadFile("/certs/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		RootCAs:      caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

type ConfigRequest struct {
	VerificationKey string   `json:"verification_key"` // hex
	PublicKeyShares []string `json:"public_key_shares"` // hex
	Threshold       uint16   `json:"threshold"`
	MaxSigners      uint16   `json:"max_signers"`
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	vkBytes, err := hex.DecodeString(req.VerificationKey)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid verification key hex")
		return
	}

	vk := agg.ciphersuite.Group().NewElement()
	if err := vk.Decode(vkBytes); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("decode verification key: %v", err))
		return
	}

	publicKeyShares := make([]*keys.PublicKeyShare, len(req.PublicKeyShares))
	for i, pksHex := range req.PublicKeyShares {
		pksBytes, err := hex.DecodeString(pksHex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid public key share %d hex", i))
			return
		}
		pks := new(keys.PublicKeyShare)
		if err := pks.Decode(pksBytes); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("decode public key share %d: %v", i, err))
			return
		}
		publicKeyShares[i] = pks
	}

	config := &frost.Configuration{
		Ciphersuite:           agg.ciphersuite,
		Threshold:             req.Threshold,
		MaxSigners:            req.MaxSigners,
		VerificationKey:       vk,
		SignerPublicKeyShares: publicKeyShares,
	}

	if err := config.Init(); err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("FROST config init: %v", err))
		return
	}

	agg.config = config
	agg.vk = vk
	agg.configured = true

	log.Printf("Aggregator configured: threshold=%d, maxSigners=%d", req.Threshold, req.MaxSigners)
	respondJSON(w, map[string]string{"status": "configured"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	respondJSON(w, map[string]interface{}{
		"status":     "ok",
		"configured": agg.configured,
	})
}

func respondError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
