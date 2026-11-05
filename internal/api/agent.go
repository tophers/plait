package api

import (
	"net/http"

	"plait/internal/controller"
	"plait/internal/protocol"
	"plait/internal/wg"
)

type enrollRequest struct {
	Token     string `json:"token"`
	PublicKey wg.Key `json:"public_key"`
}

type enrollResponse struct {
	SiteID     string `json:"site_id"`
	Credential string `json:"credential"`
}

// agentEnroll exchanges a single-use enrollment token and the gateway's
// locally generated public key for a site credential.
func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	siteID, cred, err := s.Svc.EnrollSite(r.Context(), req.Token, req.PublicKey)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.Log.Info("site enrolled", "site_id", siteID)
	writeJSON(w, http.StatusOK, enrollResponse{SiteID: siteID, Credential: cred})
}

// agentSync returns the complete desired snapshot for the authenticated site.
func (s *Server) agentSync(w http.ResponseWriter, r *http.Request) {
	a := agentFrom(r)
	if rec, err := s.Svc.InRecovery(r.Context()); err != nil || rec {
		if err == nil {
			err = errRecovery
		}
		writeError(w, err, s.Log)
		return
	}
	snap, err := s.Svc.SiteSnapshot(r.Context(), a.SiteID)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) agentStatus(w http.ResponseWriter, r *http.Request) {
	var st protocol.AgentStatus
	if err := decode(w, r, &st); err != nil {
		writeError(w, err, s.Log)
		return
	}
	if err := s.Svc.RecordStatus(r.Context(), agentFrom(r), &st); err != nil {
		writeError(w, err, s.Log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentRotate(w http.ResponseWriter, r *http.Request) {
	tok, err := s.Svc.RotateAgentCredential(r.Context(), agentFrom(r), controller.DefaultCredentialOverlap)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"credential": tok, "previous_expires_in": controller.DefaultCredentialOverlap.String()})
}
