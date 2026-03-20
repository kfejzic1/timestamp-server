package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/bytemare/frost"
)

type AggregateRequest struct {
	Message        string   `json:"message"`         // hex canonical message
	SignatureShares []string `json:"signature_shares"` // hex
	CommitmentList string   `json:"commitment_list"`  // hex
}

type AggregateResponse struct {
	Signature string `json:"signature"` // hex
}

func handleAggregate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req AggregateRequest
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

	commitListBytes, err := hex.DecodeString(req.CommitmentList)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid commitment list hex")
		return
	}

	commitments, err := frost.DecodeList(commitListBytes)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("decode commitment list: %v", err))
		return
	}

	sigShares := make([]*frost.SignatureShare, len(req.SignatureShares))
	for i, ssHex := range req.SignatureShares {
		ssBytes, err := hex.DecodeString(ssHex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid signature share %d hex", i))
			return
		}
		ss := new(frost.SignatureShare)
		if err := ss.Decode(ssBytes); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("decode signature share %d: %v", i, err))
			return
		}
		sigShares[i] = ss
	}

	// AggregateSignatures with verify=true checks each share and the final signature
	signature, err := agg.config.AggregateSignatures(msgBytes, sigShares, commitments, true)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("aggregation failed: %v", err))
		return
	}

	// Secondary verification as defense-in-depth
	if err := frost.VerifySignature(agg.ciphersuite, msgBytes, signature, agg.vk); err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("post-aggregation verification failed: %v", err))
		return
	}

	sigHex := hex.EncodeToString(signature.Encode())
	log.Printf("Signature aggregation successful: %s...", sigHex[:32])

	respondJSON(w, AggregateResponse{Signature: sigHex})
}
