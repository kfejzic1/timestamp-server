package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

type SignerState struct {
	mu sync.Mutex

	participantID uint16
	threshold     uint16
	maxSigners    uint16
	gatewayURL    string
	callbackURL   string
	encryptionKey []byte

	dkgParticipant *dkg.Participant
	dkgRound1Data  []*dkg.Round1Data

	// X25519 E2E keys for DKG share encryption
	e2ePrivKey [32]byte
	e2ePubKey  [32]byte
	peerE2EKeys map[uint16][32]byte // participantID -> X25519 public key

	// FROST signing state (post-DKG)
	keyShare       *keys.KeyShare
	pubKeyShares   []*keys.PublicKeyShare
	verificationKey []byte
	frostConfig    *frost.Configuration
	frostSigner    *frost.Signer

	dkgComplete bool
}

var state = &SignerState{
	peerE2EKeys: make(map[uint16][32]byte),
}

func main() {
	port := os.Getenv("SIGNER_PORT")
	if port == "" {
		port = "8081"
	}
	state.gatewayURL = os.Getenv("GATEWAY_URL")
	if state.gatewayURL == "" {
		state.gatewayURL = "https://gateway:8000"
	}

	threshold, _ := strconv.Atoi(os.Getenv("THRESHOLD"))
	maxSigners, _ := strconv.Atoi(os.Getenv("MAX_SIGNERS"))
	state.threshold = uint16(threshold)
	state.maxSigners = uint16(maxSigners)

	encKeyHex := os.Getenv("ENCRYPTION_KEY")
	if encKeyHex != "" {
		k, err := hex.DecodeString(encKeyHex)
		if err != nil {
			log.Fatalf("Invalid ENCRYPTION_KEY hex: %v", err)
		}
		if len(k) != 32 {
			log.Fatalf("ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d", len(k))
		}
		state.encryptionKey = k
	}

	pubKey, privKey := GenerateX25519KeyPair()
	state.e2ePubKey = pubKey
	state.e2ePrivKey = privKey

	hostname, _ := os.Hostname()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/dkg/start", handleDKGStart)
	mux.HandleFunc("/dkg/continue", handleDKGContinue)
	mux.HandleFunc("/dkg/finalize", handleDKGFinalize)
	mux.HandleFunc("/frost/config", handleFROSTConfig)
	mux.HandleFunc("/sign/commit", handleCommit)
	mux.HandleFunc("/sign/sign", handleSign)

	tlsConfig, err := buildTLSConfig()
	if err != nil {
		log.Printf("WARNING: mTLS not configured, running plain HTTP: %v", err)
		state.callbackURL = fmt.Sprintf("http://%s:%s", hostname, port)
		go registerWithGateway()
		log.Printf("Signer listening on :%s (HTTP)", port)
		log.Fatal(http.ListenAndServe(":"+port, mux))
		return
	}

	state.callbackURL = fmt.Sprintf("https://%s:%s", hostname, port)

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go registerWithGateway()

	log.Printf("Signer listening on :%s (mTLS)", port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func buildTLSConfig() (*tls.Config, error) {
	certFile := "/certs/signer.crt"
	keyFile := "/certs/signer.key"
	caFile := "/certs/ca.crt"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
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

func getHTTPClient() *http.Client {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	certFile := "/certs/signer.crt"
	keyFile := "/certs/signer.key"
	caFile := "/certs/ca.crt"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		caCert, err := os.ReadFile(caFile)
		if err == nil {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			}
		}
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
}

type RegisterRequest struct {
	CallbackURL  string `json:"callback_url"`
	X25519PubKey string `json:"x25519_pub_key"`
}

type RegisterResponse struct {
	ParticipantID uint16 `json:"participant_id"`
}

func registerWithGateway() {
	time.Sleep(2 * time.Second)

	// Check for existing key share on disk
	loaded := tryLoadKeyShare()
	if loaded {
		log.Println("Loaded existing key share from disk — will skip DKG")
	}

	reqBody := RegisterRequest{
		CallbackURL:  state.callbackURL,
		X25519PubKey: hex.EncodeToString(state.e2ePubKey[:]),
	}
	bodyBytes, _ := json.Marshal(reqBody)

	client := getHTTPClient()

	for attempt := 1; attempt <= 30; attempt++ {
		resp, err := client.Post(
			state.gatewayURL+"/api/register",
			"application/json",
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			log.Printf("Registration attempt %d failed: %v", attempt, err)
			time.Sleep(2 * time.Second)
			continue
		}

		var regResp RegisterResponse
		json.NewDecoder(resp.Body).Decode(&regResp)
		resp.Body.Close()

		state.mu.Lock()
		state.participantID = regResp.ParticipantID
		state.mu.Unlock()

		log.Printf("Registered with gateway as participant %d", regResp.ParticipantID)
		return
	}

	log.Fatal("Failed to register with gateway after 30 attempts")
}

func tryLoadKeyShare() bool {
	state.mu.Lock()
	defer state.mu.Unlock()

	if len(state.encryptionKey) == 0 {
		return false
	}

	files, err := os.ReadDir("/data")
	if err != nil {
		return false
	}

	for _, f := range files {
		if !f.IsDir() && len(f.Name()) > 4 {
			data, err := os.ReadFile("/data/" + f.Name())
			if err != nil {
				continue
			}
			plaintext, err := DecryptAESGCM(state.encryptionKey, data)
			if err != nil {
				continue
			}

			ks := new(keys.KeyShare)
			if err := ks.Decode(plaintext); err != nil {
				continue
			}

			state.keyShare = ks
			state.dkgComplete = true
			log.Printf("Loaded key share for participant %d from disk", ks.ID)
			return true
		}
	}
	return false
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()

	resp := map[string]interface{}{
		"status":         "ok",
		"participant_id": state.participantID,
		"dkg_complete":   state.dkgComplete,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
