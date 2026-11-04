package web

import (
	"embed"
	"io/fs"
)

//go:embed all:admin/dist
var adminEmbedFS embed.FS

//go:embed all:user/dist
var userEmbedFS embed.FS

func AdminFS() fs.FS {
	sub, err := fs.Sub(adminEmbedFS, "admin/dist")
	if err != nil {
		panic(err)
	}
	return sub
}

func UserFS() fs.FS {
	sub, err := fs.Sub(userEmbedFS, "user/dist")
	if err != nil {
		panic(err)
	}
	return sub
}
