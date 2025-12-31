package ldap

import (
	"crypto/tls"
	"fmt"
	"remotegateway/internal/config"
	"remotegateway/internal/hash"
	"remotegateway/internal/types"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func LdapAuthenticateAccess(username, password string) (*types.User, error) {
	conn, err := dialLDAP(config.LdapCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && config.LdapCfg.UserMailDomain != "" {
		domain := config.LdapCfg.UserMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	filter := fmt.Sprintf(config.LdapCfg.UserFilter, mail)
	fmt.Println("filter", filter)
	searchReq := ldap.NewSearchRequest(
		config.LdapCfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", mail)
	}

	return &types.User{Name: username, NtlmPassword: hash.NtlmV2Hash(password, username, "")}, nil
}

func dialLDAP(cfg config.LDAPConfig) (*ldap.Conn, error) {

	// #nosec G402 -- skip TLS verification if configured
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}))
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		// #nosec G402 -- skip TLS verification if configured
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}
