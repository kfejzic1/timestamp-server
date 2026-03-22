package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/bytemare/frost"
)

type VerifyRequest struct {
	Message   string `json:"message"`   // hex canonical message
	Signature string `json:"signature"` // hex
}

type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Detail string `json:"detail,omitempty"`
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	if !agg.configured {
		respondError(w, http.StatusPreconditionFailed, "aggregator not configured")
		return
	}

	msgBytes, err := hex.DecodeString(req.Message)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid message hex")
		return
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid signature hex")
		return
	}

	sig := new(frost.Signature)
	if err := sig.Decode(sigBytes); err != nil {
		respondJSON(w, VerifyResponse{
			Valid:  false,
			Detail: fmt.Sprintf("decode signature: %v", err),
		})
		return
	}

	if err := frost.VerifySignature(agg.ciphersuite, msgBytes, sig, agg.vk); err != nil {
		log.Printf("Verification failed: %v", err)
		respondJSON(w, VerifyResponse{
			Valid:  false,
			Detail: fmt.Sprintf("verification failed: %v", err),
		})
		return
	}

	log.Println("Signature verification successful")
	respondJSON(w, VerifyResponse{Valid: true})
}
