package pihole

type Group struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Comment      string `json:"comment"`
	Enabled      bool   `json:"enabled"`
	DateAdded    int    `json:"date_added"`
	DateModified int    `json:"date_modified"`
}

type GroupResponse struct {
	Groups []Group `json:"groups"`
	Took   float64 `json:"took"`
}

type GroupListResponse struct {
	Groups []Group `json:"groups"`
}

type ClientItem struct {
	IP      string `json:"client"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
}

type DomainItem struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"` // "allow" or "deny"
	Kind    string `json:"kind"` // "exact" or "regex"
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
}
