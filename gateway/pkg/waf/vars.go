package waf

// DefaultDirectives are default directives with early blocking enabled
var DefaultDirectives = []string{
	"Include @coraza.conf-recommended",
	"Include @crs-setup.conf.example",
	`SecAction "id:900120,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.14.0',setvar:tx.early_blocking=1"`,
	"Include @owasp_crs/*.conf",
	"SecRuleEngine On",
}
