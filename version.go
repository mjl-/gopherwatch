package main

import (
	"runtime/debug"
)

var version = "(devel)"

func init() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	version = buildInfo.Main.Version
	if version == "(devel)" {
		var vcsRev, vcsMod string
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				vcsRev = setting.Value
			} else if setting.Key == "vcs.modified" {
				vcsMod = setting.Value
			}
		}
		if vcsRev == "" {
			return
		}
		version = vcsRev
		switch vcsMod {
		case "false":
		case "true":
			version += "+modifications"
		default:
			version += "+unknown"
		}
	}
}
