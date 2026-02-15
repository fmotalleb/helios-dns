// Package config defines runtime configuration structures and helpers.
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

// Config represents application-level settings.
type Config struct {
	Listen         string        `mapstructure:"listen" default:"{{ .args.listen }}" validate:"required,hostport"`
	UpdateInterval time.Duration `mapstructure:"interval" default:"{{ .args.interval }}" validate:"gt=0"`
	Domains        []*ScanConfig `mapstructure:"domains" validate:"required,min=1"`
}

// ScanConfig defines scan settings for a single domain.
type ScanConfig struct {
	Domain     string   `mapstructure:"domain" validate:"required,fqdn"`
	CIDRs      []string `mapstructure:"cidr" validate:"required,min=1,dive,cidr"`
	SNI        string   `mapstructure:"sni" default:"{{ .args.sni }}"`
	Timeout    int      `mapstructure:"timeout" default:"{{ .args.timeout }}" validate:"gt=0"`
	Port       int      `mapstructure:"port" default:"{{ .args.port }}" validate:"gte=1,lte=65535"`
	Path       string   `mapstructure:"path" default:"{{ .args.path }}" validate:"required,path"`
	StatusCode int      `mapstructure:"status_code" default:"{{ .args.status_code }}" validate:"gte=0,lte=599"`

	SamplesMinimum int     `mapstructure:"sample_min" default:"{{ .args.sample_min }}" validate:"gte=0"`
	SamplesMaximum int     `mapstructure:"sample_max" default:"{{ .args.sample_max }}" validate:"gte=0"`
	SamplesChance  float64 `mapstructure:"sample_chance" default:"{{ .args.sample_chance }}" validate:"gte=0,lte=1"`

	HTTPOnly bool   `mapstructure:"http_only" default:"{{ .args.http_only }}"`
	Program  string `mapstructure:"program"`

	Limit int `mapstructure:"result_limit" default:"4" validate:"gt=0"`

	vm *vm.VM
}

// ReadCIDRs parses CIDR strings into iterators.
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

// ReadCIDRsSamples builds sampled IP sequences from configured CIDRs.
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

// BuildVM creates and caches the execution VM for this scan configuration.
func (sc *ScanConfig) BuildVM() (*vm.VM, error) {
	if sc.vm != nil {
		return sc.vm, nil
	}
	defaultProgram := `
tls.connect port={{ .Port }} sni={{ .SNI }} timeout={{ .Timeout }}
{{ if gt .StatusCode 0 -}} tls.http.get header.host={{ .SNI }} path={{ .Path }} expect.status={{ .StatusCode }} {{- end -}}
`
	if sc.HTTPOnly {
		defaultProgram = `
tcp.connect port={{ .Port }} timeout={{ .Timeout }}
{{ if gt .StatusCode 0 -}} http.get port={{ .Port }} path={{ .Path }} expect.status={{ .StatusCode }} headers.host={{ .SNI }} timeout={{ .Timeout }} {{- end -}}
`
	}
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
