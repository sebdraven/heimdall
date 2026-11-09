package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

// linkStore is what linking a name to a campaign reads and writes.
type linkStore interface {
	Campaigns(ctx context.Context) ([]pg.Campaign, error)
	Campaign(ctx context.Context, id int64) (pg.Campaign, error)
	CreateCampaign(ctx context.Context, name, family, description string) (pg.Campaign, error)
	Domain(ctx context.Context, fqdn string) (pg.Domain, error)
	ImportDomains(ctx context.Context, fqdns []string, campaignID *int64, intervalSeconds int, source string, addedBy *int64) (int64, error)
	UpdateDomain(ctx context.Context, fqdn string, p pg.DomainPatch) (pg.Domain, error)
}

const (
	linkAdded     = "added"
	linkMoved     = "moved"
	linkUnchanged = "unchanged"
)

type campaignRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type linkJSON struct {
	FQDN            string      `json:"fqdn"`
	Campaign        campaignRef `json:"campaign"`
	Action          string      `json:"action"`
	CreatedCampaign bool        `json:"created_campaign"`
}

// linkDomainPage serves POST /domains/{fqdn}/link.
func (s *server) linkDomainPage(w http.ResponseWriter, r *http.Request) { s.linkDomain(w, r, "web:") }

// linkDomainAPI serves POST /api/domains/{fqdn}/link.
func (s *server) linkDomainAPI(w http.ResponseWriter, r *http.Request) { s.linkDomain(w, r, "api:") }

// linkDomain puts the name of the path in the campaign of the body,
// {"campaign": id} or {"new_campaign": {"name", "description"}}, created
// first: it is added to the watchlist, or moved to that campaign.
func (s *server) linkDomain(w http.ResponseWriter, r *http.Request, source string) {
	fqdn, err := resolver.NormalizeFQDN(r.PathValue("fqdn"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid fqdn")
		return
	}
	var req struct {
		Campaign    *int64 `json:"campaign"`
		NewCampaign *struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"new_campaign"`
	}
	if err := decodeJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if (req.Campaign == nil) == (req.NewCampaign == nil) {
		apiError(w, http.StatusBadRequest, "campaign or new_campaign")
		return
	}
	out := linkJSON{FQDN: fqdn}
	var c pg.Campaign
	if nc := req.NewCampaign; nc != nil {
		name := strings.TrimSpace(nc.Name)
		if name == "" {
			apiError(w, http.StatusBadRequest, "name is required")
			return
		}
		c, err = s.links.CreateCampaign(r.Context(), name, "", strings.TrimSpace(nc.Description))
		if errors.Is(err, pg.ErrConflict) {
			apiError(w, http.StatusConflict, "campaign exists")
			return
		}
		if err != nil {
			s.apiStoreError(w, r, err)
			return
		}
		s.audit(r, "campaign.create", c.Name)
		out.CreatedCampaign = true
	} else {
		c, err = s.links.Campaign(r.Context(), *req.Campaign)
		if errors.Is(err, pg.ErrNotFound) {
			apiError(w, http.StatusNotFound, "unknown campaign")
			return
		}
		if err != nil {
			s.apiStoreError(w, r, err)
			return
		}
	}
	out.Campaign = campaignRef{ID: c.ID, Name: c.Name}
	if out.Action, err = s.linkWatched(r, fqdn, c, source); err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// linkWatched adds fqdn to the watchlist in c, or moves it to c.
func (s *server) linkWatched(r *http.Request, fqdn string, c pg.Campaign, source string) (string, error) {
	ctx := r.Context()
	d, err := s.links.Domain(ctx, fqdn)
	switch {
	case errors.Is(err, pg.ErrNotFound):
		u := auth.UserFrom(ctx)
		n, ierr := s.links.ImportDomains(ctx, []string{fqdn}, &c.ID, defaultInterval, source+u.Username, &u.ID)
		if ierr != nil {
			return "", ierr
		}
		if n > 0 {
			s.audit(r, "domain.import", fmt.Sprintf("%s (%s)", c.Name, fqdn))
			return linkAdded, nil
		}
		// Added meanwhile.
		if d, err = s.links.Domain(ctx, fqdn); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	}
	if d.CampaignID != nil && *d.CampaignID == c.ID {
		return linkUnchanged, nil
	}
	if _, err := s.links.UpdateDomain(ctx, fqdn, pg.DomainPatch{SetCampaign: true, CampaignID: &c.ID}); err != nil {
		return "", err
	}
	s.audit(r, "domain.update", fqdn)
	return linkMoved, nil
}

// linkCampaigns lists the campaigns of the "Link to campaign" dialog, nil
// below the analyst role.
func (s *server) linkCampaigns(r *http.Request) ([]campaignRef, error) {
	if u := auth.UserFrom(r.Context()); u == nil || !auth.Allowed(u.Role, auth.RoleAnalyst) {
		return nil, nil
	}
	cs, err := s.links.Campaigns(r.Context())
	if err != nil {
		return nil, err
	}
	out := make([]campaignRef, 0, len(cs))
	for _, c := range cs {
		out = append(out, campaignRef{ID: c.ID, Name: c.Name})
	}
	return out, nil
}

// setLink gives an analyst's graph page the campaigns of the dialog and the
// current one: id, else the campaign of root, if any.
func (s *server) setLink(r *http.Request, v *graphView, id int64, root string) error {
	cs, err := s.linkCampaigns(r)
	if err != nil || cs == nil {
		return err
	}
	v.Campaigns, v.CurrentCampaign = cs, id
	if id != 0 || root == "" {
		return nil
	}
	watched, err := s.graph.DomainsByFQDN(r.Context(), []string{root})
	if err != nil {
		return err
	}
	if d, ok := watched[root]; ok && d.CampaignID != nil {
		v.CurrentCampaign = *d.CampaignID
	}
	return nil
}
