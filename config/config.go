package config

import (
	"cmp"
	"iter"
	"net"
	"time"

	"github.com/fmotalleb/go-tools/template"
	"github.com/fmotalleb/mithra/cidr"
	"github.com/fmotalleb/mithra/vm"
)

type Config struct {
	Listen         string        `mapstructure:"listen" default:"{{ .args.listen }}"`
	UpdateInterval time.Duration `mapstructure:"interval" default:"{{ .args.interval }}"`
	Domains        []*ScanConfig `mapstructure:"domains"`
}

type ScanConfig struct {
	Domain     string   `mapstructure:"domain"`
	CIDRs      []string `mapstructure:"cidr"`
	SNI        string   `mapstructure:"sni" default:"{{ .args.sni }}"`
	Timeout    int      `mapstructure:"timeout" default:"{{ .args.timeout }}"`
	Port       int      `mapstructure:"port" default:"{{ .args.port }}"`
	StatusCode int      `mapstructure:"status_code" default:"{{ .args.status_code }}"`

	SamplesMinimum int     `mapstructure:"sample_min" default:"{{ .args.sample_min }}"`
	SamplesMaximum int     `mapstructure:"sample_max" default:"{{ .args.sample_max }}"`
	SamplesChance  float64 `mapstructure:"sample_chance" default:"{{ .args.sample_chance }}"`

	Program string `mapstructure:"program"`

	Limit int `mapstructure:"result_limit" default:"4"`

	vm *vm.VM
}

func (sc *ScanConfig) ReadCIDRs() ([]*cidr.Iterator, error) {
	result := make([]*cidr.Iterator, len(sc.CIDRs))
	var err error
	for i, cidrStr := range sc.CIDRs {
		result[i], err = cidr.NewIPv4CIDR(cidrStr)
		if err != nil {
			return result, err
		}
	}
	return result, err
}

func (sc *ScanConfig) ReadCIDRsSamples() ([]iter.Seq[net.IP], error) {
	cidrs, err := sc.ReadCIDRs()
	if err != nil {
		return nil, err
	}
	samples := make([]iter.Seq[net.IP], len(cidrs))
	for i, iter := range cidrs {
		samples[i] = iter.SeqSampled(sc.SamplesChance, sc.SamplesMaximum, sc.SamplesMinimum)
	}
	return samples, nil
}

func (sc *ScanConfig) BuildVM() (*vm.VM, error) {
	if sc.vm != nil {
		return sc.vm, nil
	}
	defaultProgram := `
tls.connect port={{ .Port }} sni={{ .SNI }} timeout={{ .Timeout }}
{{ if gt .StatusCode 0 -}} tls.http.get header.host={{ .SNI }} path=/ expect.status={{ .StatusCode }} {{- end -}}
`
	programStr := cmp.Or(sc.Program, defaultProgram)
	program, err := template.EvaluateTemplate(programStr, sc)
	if err != nil {
		return nil, err
	}
	vmRuntime, err := vm.New([]byte(program))
	if err == nil {
		sc.vm = vmRuntime
	}
	return vmRuntime, err
}
