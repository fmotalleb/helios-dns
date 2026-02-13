package config

import (
	"cmp"
	"time"

	"github.com/fmotalleb/go-tools/template"
	mithra "github.com/fmotalleb/mithra/config"
	"github.com/fmotalleb/mithra/vm"
)

type Config struct {
	Listen         string                `mapstructure:"listen" default:"{{ .args.listen }}"`
	UpdateInterval time.Duration         `mapstructure:"interval" default:"{{ .args.interval }}"`
	Domains        map[string]ScanConfig `mapstructure:"domains"`
}

type ScanConfig struct {
	mithra.Config
	Limit int `mapstructure:"result_limit"`

	vm *vm.VM
}

func (cfg *ScanConfig) BuildVM() (*vm.VM, error) {
	if cfg.vm != nil {
		return cfg.vm, nil
	}
	defaultProgram := `
tls.connect port={{ .Port }} sni={{ .SNI }} timeout={{ .Timeout }}
{{ if gt .StatusCode 0 -}} tls.http.get header.host={{ .SNI }} path=/ expect.status={{ .StatusCode }} {{- end -}}
`
	programStr := cmp.Or(cfg.Program, defaultProgram)
	program, err := template.EvaluateTemplate(programStr, cfg)
	if err != nil {
		return nil, err
	}
	vmRuntime, err := vm.New([]byte(program))
	if err == nil {
		cfg.vm = vmRuntime
	}
	return vmRuntime, err
}
