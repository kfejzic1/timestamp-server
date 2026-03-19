package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

type DKGStartRequest struct {
	PeerE2EKeys map[uint16]string `json:"peer_e2e_keys"` // participantID -> hex X25519 pubkey
}

type DKGStartResponse struct {
	Round1Data string `json:"round1_data"` // hex
}

func handleDKGStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req DKGStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.dkgComplete {
		respondError(w, http.StatusConflict, "DKG already completed")
		return
	}

	for id, keyHex := range req.PeerE2EKeys {
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != 32 {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid E2E key for peer %d", id))
			return
		}
		var key [32]byte
		copy(key[:], keyBytes)
		state.peerE2EKeys[id] = key
	}

	ciphersuite := dkg.Ristretto255Sha512
	participant, err := ciphersuite.NewParticipant(
		state.participantID,
		state.threshold,
		state.maxSigners,
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("DKG init failed: %v", err))
		return
	}
	state.dkgParticipant = participant

	round1 := participant.Start()
	round1Hex := hex.EncodeToString(round1.Encode())

	log.Printf("DKG Round 1 complete for participant %d", state.participantID)
	respondJSON(w, DKGStartResponse{Round1Data: round1Hex})
}

type DKGContinueRequest struct {
	Round1DataAll []string `json:"round1_data_all"` // hex-encoded Round1Data from all participants
}

type DKGContinueResponse struct {
	Round2Data map[uint16]string `json:"round2_data"` // recipientID -> hex(E2E-encrypted Round2Data)
}

func handleDKGContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req DKGContinueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.dkgParticipant == nil {
		respondError(w, http.StatusPreconditionFailed, "DKG not started")
		return
	}

	round1Data := make([]*dkg.Round1Data, len(req.Round1DataAll))
	for i, r1hex := range req.Round1DataAll {
		r1bytes, err := hex.DecodeString(r1hex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid round1 hex at index %d", i))
			return
		}
		r1 := new(dkg.Round1Data)
		if err := r1.Decode(r1bytes); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("decode round1 failed at index %d: %v", i, err))
			return
		}
		round1Data[i] = r1
	}

	state.dkgRound1Data = round1Data

	round2Map, err := state.dkgParticipant.Continue(round1Data)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("DKG Continue failed: %v", err))
		return
	}

	encryptedR2 := make(map[uint16]string)
	for recipientID, r2data := range round2Map {
		plaintext := r2data.Encode()

		recipientPubKey, ok := state.peerE2EKeys[recipientID]
		if !ok {
			respondError(w, http.StatusInternalServerError,
				fmt.Sprintf("no E2E key for recipient %d", recipientID))
			return
		}

		ciphertext, err := SealBox(plaintext, recipientPubKey, state.e2ePrivKey)
		if err != nil {
			respondError(w, http.StatusInternalServerError,
				fmt.Sprintf("E2E encrypt failed for %d: %v", recipientID, err))
			return
		}
		encryptedR2[recipientID] = hex.EncodeToString(ciphertext)
	}

	log.Printf("DKG Round 2 complete for participant %d, sending %d shares", state.participantID, len(encryptedR2))
	respondJSON(w, DKGContinueResponse{Round2Data: encryptedR2})
}

type DKGFinalizeRequest struct {
	Round2DataForMe map[uint16]string `json:"round2_data_for_me"` // senderID -> hex(E2E-encrypted data)
}

type DKGFinalizeResponse struct {
	PublicKeyShare  string `json:"public_key_share"`  // hex
	VerificationKey string `json:"verification_key"`  // hex
}

func handleDKGFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req DKGFinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.dkgParticipant == nil {
		respondError(w, http.StatusPreconditionFailed, "DKG not started")
		return
	}

	round2Data := make([]*dkg.Round2Data, 0, len(req.Round2DataForMe))
	for senderID, encHex := range req.Round2DataForMe {
		ciphertext, err := hex.DecodeString(encHex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid hex from sender %d", senderID))
			return
		}

		senderPubKey, ok := state.peerE2EKeys[senderID]
		if !ok {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("no E2E key for sender %d", senderID))
			return
		}

		plaintext, err := OpenBox(ciphertext, senderPubKey, state.e2ePrivKey)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("E2E decrypt failed from sender %d: %v", senderID, err))
			return
		}

		r2 := new(dkg.Round2Data)
		if err := r2.Decode(plaintext); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("decode round2 from %d failed: %v", senderID, err))
			return
		}
		round2Data = append(round2Data, r2)
	}

	keyShare, err := state.dkgParticipant.Finalize(state.dkgRound1Data, round2Data)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("DKG Finalize failed: %v", err))
		return
	}

	state.keyShare = keyShare
	state.dkgComplete = true

	if len(state.encryptionKey) > 0 {
		encData, err := EncryptAESGCM(state.encryptionKey, keyShare.Encode())
		if err != nil {
			log.Printf("WARNING: failed to encrypt key share: %v", err)
		} else {
			path := fmt.Sprintf("/data/keyshare_%d.enc", state.participantID)
			if err := os.WriteFile(path, encData, 0600); err != nil {
				log.Printf("WARNING: failed to persist key share: %v", err)
			} else {
				log.Printf("Key share persisted to %s", path)
			}
		}
	}

	pubKeyShare := keyShare.Public()
	vkBytes := keyShare.VerificationKey.Encode()

	log.Printf("DKG Finalize complete for participant %d", state.participantID)
	respondJSON(w, DKGFinalizeResponse{
		PublicKeyShare:  hex.EncodeToString(pubKeyShare.Encode()),
		VerificationKey: hex.EncodeToString(vkBytes),
	})
}

func initFROSTConfig(pubKeySharesHex []string, verificationKeyHex string) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	ciphersuite := frost.Ristretto255

	vkBytes, err := hex.DecodeString(verificationKeyHex)
	if err != nil {
		return fmt.Errorf("decode verification key: %w", err)
	}

	vk := ciphersuite.Group().NewElement()
	if err := vk.Decode(vkBytes); err != nil {
		return fmt.Errorf("decode verification key element: %w", err)
	}

	publicKeyShares := make([]*keys.PublicKeyShare, len(pubKeySharesHex))
	for i, pksHex := range pubKeySharesHex {
		pksBytes, err := hex.DecodeString(pksHex)
		if err != nil {
			return fmt.Errorf("decode public key share %d: %w", i, err)
		}
		pks := new(keys.PublicKeyShare)
		if err := pks.Decode(pksBytes); err != nil {
			return fmt.Errorf("decode public key share struct %d: %w", i, err)
		}
		publicKeyShares[i] = pks
	}

	config := &frost.Configuration{
		Ciphersuite:          ciphersuite,
		Threshold:            state.threshold,
		MaxSigners:           state.maxSigners,
		VerificationKey:      vk,
		SignerPublicKeyShares: publicKeyShares,
	}

	if err := config.Init(); err != nil {
		return fmt.Errorf("FROST config init: %w", err)
	}

	state.frostConfig = config
	state.pubKeyShares = publicKeyShares
	state.verificationKey = vkBytes

	signer, err := config.Signer(state.keyShare)
	if err != nil {
		return fmt.Errorf("create FROST signer: %w", err)
	}
	state.frostSigner = signer

	log.Printf("FROST configuration initialized for participant %d", state.participantID)
	return nil
}
