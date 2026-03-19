package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/bytemare/frost"
)

type FROSTConfigRequest struct {
	VerificationKey string   `json:"verification_key"`
	PublicKeyShares []string `json:"public_key_shares"`
}

func handleFROSTConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req FROSTConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := initFROSTConfig(req.PublicKeyShares, req.VerificationKey); err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("FROST config: %v", err))
		return
	}

	respondJSON(w, map[string]string{"status": "configured"})
}

type CommitRequest struct {
	SessionID string `json:"session_id"`
}

type CommitResponse struct {
	Commitment    string `json:"commitment"`     // hex
	ParticipantID uint16 `json:"participant_id"`
}

type SignRequest struct {
	SessionID      string `json:"session_id"`
	CanonicalMsg   string `json:"canonical_message"` // hex-encoded canonical binary
	CommitmentList string `json:"commitment_list"`   // hex-encoded CommitmentList
}

type SignResponse struct {
	SignatureShare string `json:"signature_share"` // hex
	ParticipantID  uint16 `json:"participant_id"`
}

func handleCommit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req CommitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.dkgComplete {
		respondError(w, http.StatusPreconditionFailed, "DKG not complete")
		return
	}

	if state.frostSigner == nil {
		respondError(w, http.StatusPreconditionFailed, "FROST signer not initialized — call /frost/config first")
		return
	}

	commitment := state.frostSigner.Commit()
	commitmentHex := hex.EncodeToString(commitment.Encode())

	log.Printf("Commitment generated for session %s by participant %d", req.SessionID, state.participantID)
	respondJSON(w, CommitResponse{
		Commitment:    commitmentHex,
		ParticipantID: state.participantID,
	})
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	msgBytes, err := hex.DecodeString(req.CanonicalMsg)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid canonical message hex")
		return
	}

	ts, err := ParseTimestampFromCanonical(msgBytes)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("parse timestamp: %v", err))
		return
	}

	if err := ValidateTimestamp(ts); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("timestamp validation: %v", err))
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

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.frostSigner == nil {
		respondError(w, http.StatusPreconditionFailed, "FROST signer not initialized")
		return
	}

	sigShare, err := state.frostSigner.Sign(msgBytes, commitments)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("signing failed: %v", err))
		return
	}

	sigShareHex := hex.EncodeToString(sigShare.Encode())

	log.Printf("Signature share generated for session %s by participant %d", req.SessionID, state.participantID)
	respondJSON(w, SignResponse{
		SignatureShare: sigShareHex,
		ParticipantID:  state.participantID,
	})
}
