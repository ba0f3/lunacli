package onboard

import (
	"fmt"
	"os"
	"path/filepath"
)

type Target int

const (
	TargetUserWide Target = iota
	TargetProjectLocal
)

type Layout struct {
	ConfigJSON   string
	ConfigRoot   string
	ConfigDirRel string
	PolicyDir    string
	TokenFile    string
}

func NewLayout(target Target) (Layout, error) {
	switch target {
	case TargetUserWide:
		home, err := os.UserHomeDir()
		if err != nil {
			return Layout{}, err
		}
		root := filepath.Join(home, ".config", "luna")
		return Layout{
			ConfigJSON:   filepath.Join(root, "luna.config.json"),
			ConfigRoot:   root,
			ConfigDirRel: "luna.d",
			PolicyDir:    filepath.Join(root, "luna.d"),
			TokenFile:    filepath.Join(root, "telegram-bot-token"),
		}, nil
	case TargetProjectLocal:
		cwd, err := os.Getwd()
		if err != nil {
			return Layout{}, err
		}
		return Layout{
			ConfigJSON:   filepath.Join(cwd, "luna.config.json"),
			ConfigRoot:   cwd,
			ConfigDirRel: "./luna.d",
			PolicyDir:    filepath.Join(cwd, "luna.d"),
			TokenFile:    filepath.Join(cwd, "telegram-bot-token"),
		}, nil
	default:
		return Layout{}, fmt.Errorf("unknown target %d", target)
	}
}
