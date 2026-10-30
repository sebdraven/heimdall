package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/config"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const usage = `usage: heimdall-cli <command> <action> [flags]

  user add --username NAME --role viewer|analyst|admin [--password-stdin]
  user list
  user passwd --username NAME [--password-stdin]
  user role --username NAME --role ROLE
  user disable --username NAME
  user enable --username NAME
  token create --username NAME --label LABEL
  token list
  token revoke --id ID
  domain import --file PATH --campaign NAME [--interval SECONDS]
  resolver add --address HOST:PORT [--label LABEL] [--qps N]
  resolver list

Connects to Postgres using HEIMDALL_PG_DSN.
`

var errUsage = errors.New("usage")

type command func(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error

var commands = map[string]command{
	"user add":      userAdd,
	"user list":     userList,
	"user passwd":   userPasswd,
	"user role":     userRole,
	"user disable":  userSetDisabled(true),
	"user enable":   userSetDisabled(false),
	"token create":  tokenCreate,
	"token list":    tokenList,
	"token revoke":  tokenRevoke,
	"domain import": domainImport,
	"resolver add":  resolverAdd,
	"resolver list": resolverList,
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	name := args[0] + " " + args[1]
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", name, usage)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	s, err := pg.Open(ctx, cfg.PGDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: postgres:", err)
		return 1
	}
	defer s.Close()

	fs := flag.NewFlagSet("heimdall-cli "+name, flag.ContinueOnError)
	if err := cmd(ctx, s, fs, args[2:]); err != nil {
		switch {
		case errors.Is(err, flag.ErrHelp):
			return 2
		case errors.Is(err, errUsage):
			fmt.Fprintln(os.Stderr, "error:", err)
			fs.Usage()
			return 2
		default:
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	return 0
}

func required(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: --%s is required", errUsage, name)
	}
	return nil
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return nil
}

func audit(ctx context.Context, s *pg.Store, action, target string) {
	if err := s.Audit(ctx, nil, "cli:"+action, target); err != nil {
		fmt.Fprintln(os.Stderr, "warning: audit log:", err)
	}
}

func userAdd(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	username := fs.String("username", "", "username")
	role := fs.String("role", "", "viewer, analyst or admin")
	stdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("username", *username); err != nil {
		return err
	}
	if !auth.ValidUsername(*username) {
		return fmt.Errorf("%w: invalid username (allowed: letters, digits, '.', '_', '-'; max 64)", errUsage)
	}
	if !auth.ValidRole(*role) {
		return fmt.Errorf("%w: --role must be one of %s", errUsage, strings.Join(auth.Roles, ", "))
	}
	hash, err := newPasswordHash(*stdin)
	if err != nil {
		return err
	}
	u, err := s.CreateUser(ctx, *username, hash, *role)
	if err != nil {
		return err
	}
	audit(ctx, s, "user.add", u.Username+" ("+u.Role+")")
	fmt.Printf("user %s created with role %s\n", u.Username, u.Role)
	return nil
}

func userList(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	if err := parse(fs, args); err != nil {
		return err
	}
	users, err := s.Users(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSERNAME\tROLE\tDISABLED\tCREATED\tLAST LOGIN")
	for _, u := range users {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%t\t%s\t%s\n", u.ID, u.Username, u.Role, u.Disabled, fmtTime(&u.CreatedAt), fmtTime(u.LastLoginAt))
	}
	return tw.Flush()
}

func userPasswd(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	username := fs.String("username", "", "username")
	stdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("username", *username); err != nil {
		return err
	}
	hash, err := newPasswordHash(*stdin)
	if err != nil {
		return err
	}
	if err := s.SetPassword(ctx, *username, hash); err != nil {
		return err
	}
	audit(ctx, s, "user.passwd", *username)
	fmt.Printf("password updated for %s; existing sessions revoked\n", *username)
	return nil
}

func userRole(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	username := fs.String("username", "", "username")
	role := fs.String("role", "", "viewer, analyst or admin")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("username", *username); err != nil {
		return err
	}
	if !auth.ValidRole(*role) {
		return fmt.Errorf("%w: --role must be one of %s", errUsage, strings.Join(auth.Roles, ", "))
	}
	if err := s.SetRole(ctx, *username, *role); err != nil {
		return err
	}
	audit(ctx, s, "user.role", *username+" ("+*role+")")
	fmt.Printf("%s is now %s\n", *username, *role)
	return nil
}

func userSetDisabled(disabled bool) command {
	return func(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
		username := fs.String("username", "", "username")
		if err := parse(fs, args); err != nil {
			return err
		}
		if err := required("username", *username); err != nil {
			return err
		}
		if err := s.SetDisabled(ctx, *username, disabled); err != nil {
			return err
		}
		action := map[bool]string{true: "user.disable", false: "user.enable"}[disabled]
		audit(ctx, s, action, *username)
		fmt.Printf("%s: %s\n", action, *username)
		return nil
	}
}

func tokenCreate(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	username := fs.String("username", "", "owner; the token inherits this user's role")
	label := fs.String("label", "", "free-form label")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("username", *username); err != nil {
		return err
	}
	if err := required("label", *label); err != nil {
		return err
	}
	u, err := s.UserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("user %s: %w", *username, err)
	}
	token, sum, err := auth.NewToken()
	if err != nil {
		return err
	}
	id, err := s.CreateToken(ctx, sum, u.ID, *label)
	if err != nil {
		return err
	}
	audit(ctx, s, "token.create", fmt.Sprintf("%d %s (%s)", id, *label, u.Username))
	fmt.Fprintf(os.Stderr, "token %d created for %s (%s). It is shown only once:\n", id, u.Username, u.Role)
	fmt.Println(token)
	return nil
}

func tokenList(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	if err := parse(fs, args); err != nil {
		return err
	}
	tokens, err := s.Tokens(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSER\tLABEL\tCREATED\tLAST USED\tREVOKED")
	for _, t := range tokens {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%t\n", t.ID, t.Username, t.Label, fmtTime(&t.CreatedAt), fmtTime(t.LastUsedAt), t.Revoked)
	}
	return tw.Flush()
}

func tokenRevoke(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	id := fs.Int64("id", 0, "token id (see token list)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *id <= 0 {
		return fmt.Errorf("%w: --id is required", errUsage)
	}
	if err := s.RevokeToken(ctx, *id); err != nil {
		return err
	}
	audit(ctx, s, "token.revoke", fmt.Sprint(*id))
	fmt.Printf("token %d revoked\n", *id)
	return nil
}

func domainImport(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	file := fs.String("file", "", "file with one FQDN per line; '#' starts a comment")
	campaign := fs.String("campaign", "", "campaign name (created if missing)")
	interval := fs.Int("interval", 300, "resolution interval in seconds")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("file", *file); err != nil {
		return err
	}
	if err := required("campaign", *campaign); err != nil {
		return err
	}
	if *interval < 10 {
		return fmt.Errorf("%w: --interval must be at least 10", errUsage)
	}

	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()
	fqdns, err := readFQDNs(f)
	if err != nil {
		return err
	}
	if len(fqdns) == 0 {
		return errors.New("no FQDN found")
	}

	c, err := s.CampaignByName(ctx, *campaign)
	if errors.Is(err, pg.ErrNotFound) {
		if c, err = s.CreateCampaign(ctx, *campaign, "", ""); err == nil {
			audit(ctx, s, "campaign.create", c.Name)
			fmt.Fprintf(os.Stderr, "campaign %s created\n", c.Name)
		}
	}
	if err != nil {
		return err
	}

	n, err := s.ImportDomains(ctx, fqdns, &c.ID, *interval, "import:"+filepath.Base(*file), nil)
	if err != nil {
		return err
	}
	audit(ctx, s, "domain.import", fmt.Sprintf("%s (%d new of %d)", c.Name, n, len(fqdns)))
	fmt.Printf("%d imported, %d already watched\n", n, int64(len(fqdns))-n)
	return nil
}

// readFQDNs rejects the whole file if any line is invalid.
func readFQDNs(r io.Reader) ([]string, error) {
	var out, bad []string
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text, _, _ := strings.Cut(sc.Text(), "#")
		if strings.TrimSpace(text) == "" {
			continue
		}
		fqdn, err := resolver.NormalizeFQDN(text)
		if err != nil {
			bad = append(bad, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		if _, dup := seen[fqdn]; !dup {
			seen[fqdn] = struct{}{}
			out = append(out, fqdn)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%d invalid line(s), nothing imported:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	return out, nil
}

func resolverAdd(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	address := fs.String("address", "", "resolver host:port (port defaults to 53)")
	label := fs.String("label", "", "free-form label")
	qps := fs.Int("qps", 20, "max queries per second sent to this resolver")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("address", *address); err != nil {
		return err
	}
	if *qps <= 0 {
		return fmt.Errorf("%w: --qps must be positive", errUsage)
	}
	addr, err := resolver.NormalizeServer(*address)
	if err != nil {
		return err
	}
	r, err := s.CreateResolver(ctx, addr, *label, *qps)
	if err != nil {
		return err
	}
	audit(ctx, s, "resolver.create", r.Address)
	fmt.Printf("resolver %d added: %s (%d qps)\n", r.ID, r.Address, r.QPS)
	return nil
}

func resolverList(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	if err := parse(fs, args); err != nil {
		return err
	}
	rs, err := s.Resolvers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tADDRESS\tLABEL\tQPS\tENABLED")
	for _, r := range rs {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%t\n", r.ID, r.Address, r.Label, r.QPS, r.Enabled)
	}
	return tw.Flush()
}

func newPasswordHash(fromStdin bool) (string, error) {
	pw, err := readPassword(fromStdin)
	if err != nil {
		return "", err
	}
	if len([]rune(pw)) < auth.MinPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", auth.MinPasswordLen)
	}
	return auth.HashPassword(pw)
}

func readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; use --password-stdin")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(p1, p2) {
		return "", errors.New("passwords do not match")
	}
	return string(p1), nil
}

func fmtTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
