package config

import (
	"os"
	"strings"
)

var (
	LdapCfg = LoadLDAPConfig()
)

type LDAPConfig struct {
	URL            string
	BaseDN         string
	UserFilter     string
	UserMailDomain string
	StartTLS       bool
	SkipTLSVerify  bool
}

func LoadLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:            getEnv("LDAP_URL", "ldaps://ldap:389"),
		BaseDN:         getEnv("LDAP_BASE_DN", "dc=glauth,dc=com"),
		UserFilter:     getEnv("LDAP_USER_FILTER", "(mail=%s)"),
		UserMailDomain: getEnv("LDAP_USER_DOMAIN", "@example.com"),
		StartTLS:       getEnvBool("LDAP_STARTTLS", false),
		SkipTLSVerify:  getEnvBool("LDAP_SKIP_TLS_VERIFY", true),
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "1" || v == "true" || v == "yes"
	}
	return def
}
