package main

import (
	"net/url"
	"os"
	"strings"
)

var (
	upstream = mustParse("http://registry:5000")
	ldapCfg  = loadLDAPConfig()
)

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func loadLDAPConfig() LDAPConfig {
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
