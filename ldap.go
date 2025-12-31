package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type User struct {
	Name         string
	NtlmPassword []byte
}

type LDAPConfig struct {
	URL            string
	BaseDN         string
	UserFilter     string
	UserMailDomain string
	StartTLS       bool
	SkipTLSVerify  bool
}

func ldapAuthenticateAccess(username, password string) (*User, error) {
	conn, err := dialLDAP(ldapCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && ldapCfg.UserMailDomain != "" {
		domain := ldapCfg.UserMailDomain
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

	filter := fmt.Sprintf(ldapCfg.UserFilter, mail)
	fmt.Println("filter", filter)
	searchReq := ldap.NewSearchRequest(
		ldapCfg.BaseDN,
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

	return &User{Name: username, NtlmPassword: ntlmV2Hash(password, username, "")}, nil
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {

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
