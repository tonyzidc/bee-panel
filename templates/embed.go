package templates

import (
	_ "embed"
)

//go:embed nginx_vhost.conf.tmpl
var NginxVHostTemplate string
