package auth

const (
	RoleViewer  = "viewer"
	RoleAnalyst = "analyst"
	RoleAdmin   = "admin"
)

var Roles = []string{RoleViewer, RoleAnalyst, RoleAdmin}

var rank = map[string]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}

func ValidRole(role string) bool { return rank[role] > 0 }

func Allowed(have, need string) bool {
	return rank[need] > 0 && rank[have] >= rank[need]
}
