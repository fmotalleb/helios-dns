package config

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/miekg/dns"
)

var (
	validateOnce sync.Once
	validateInst *validator.Validate
)

func validatorInstance() *validator.Validate {
	validateOnce.Do(func() {
		validateInst = validator.New()
		validateInst.RegisterTagNameFunc(func(field reflect.StructField) string {
			tag := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
			if tag == "" || tag == "-" {
				return field.Name
			}
			return tag
		})
		_ = validateInst.RegisterValidation("hostport", validateHostPort)
		_ = validateInst.RegisterValidation("fqdn", validateFQDN)
		_ = validateInst.RegisterValidation("path", validateHTTPPath)
		validateInst.RegisterStructValidation(validateScanConfigStruct, ScanConfig{})
	})
	return validateInst
}

func validateHostPort(fl validator.FieldLevel) bool {
	value, ok := fl.Field().Interface().(string)
	if !ok || strings.TrimSpace(value) == "" {
		return false
	}
	_, _, err := net.SplitHostPort(value)
	return err == nil
}

func validateFQDN(fl validator.FieldLevel) bool {
	value, ok := fl.Field().Interface().(string)
	if !ok || strings.TrimSpace(value) == "" {
		return false
	}
	_, valid := dns.IsDomainName(value)
	return valid && dns.IsFqdn(value)
}

func validateHTTPPath(fl validator.FieldLevel) bool {
	value, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	return strings.HasPrefix(value, "/")
}

func validateScanConfigStruct(sl validator.StructLevel) {
	cfg, ok := sl.Current().Interface().(ScanConfig)
	if !ok {
		return
	}
	if cfg.SamplesMaximum > 0 && cfg.SamplesMinimum > cfg.SamplesMaximum {
		sl.ReportError(cfg.SamplesMinimum, "sample_min", "sample_min", "sample_bounds", "")
	}
}

// Validate checks whether the parsed configuration is usable.
func (cfg *Config) Validate() error {
	v := validatorInstance()
	errs := make([]error, 0)

	if err := v.Struct(cfg); err != nil {
		errs = append(errs, formatValidationErrors(err, ""))
	}

	for i, domainCfg := range cfg.Domains {
		if domainCfg == nil {
			errs = append(errs, fmt.Errorf("domains[%d]: must not be null", i))
			continue
		}
		if err := v.Struct(domainCfg); err != nil {
			errs = append(errs, formatValidationErrors(err, fmt.Sprintf("domains[%d]: ", i)))
		}
	}
	return errors.Join(errs...)
}

// Validate checks whether the per-domain scan configuration is usable.
func (sc *ScanConfig) Validate() error {
	return formatValidationErrors(validatorInstance().Struct(sc), "")
}

func formatValidationErrors(err error, prefix string) error {
	if err == nil {
		return nil
	}
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return err
	}

	list := make([]error, 0, len(verrs))
	for _, verr := range verrs {
		field := verr.Field()
		switch field {
		case "Domains":
			field = "domains"
		}
		switch verr.Tag() {
		case "required":
			list = append(list, fmt.Errorf("%s%s: is required", prefix, field))
		case "min":
			if field == "domains" {
				list = append(list, fmt.Errorf("%sdomains: must contain at least one item", prefix))
				continue
			}
			list = append(list, fmt.Errorf("%s%s: must contain at least one item", prefix, field))
		case "hostport":
			list = append(list, fmt.Errorf("%slisten: invalid address", prefix))
		case "fqdn":
			list = append(list, fmt.Errorf("%sdomain: must be a valid FQDN (got %q)", prefix, verr.Value()))
		case "cidr":
			list = append(list, fmt.Errorf("%scidr: invalid CIDR %q", prefix, verr.Value()))
		case "path":
			list = append(list, fmt.Errorf("%spath: must start with '/' (got %q)", prefix, verr.Value()))
		case "gt":
			list = append(list, fmt.Errorf("%s%s: must be greater than zero", prefix, field))
		case "gte":
			list = append(list, fmt.Errorf("%s%s: out of range", prefix, field))
		case "lte":
			list = append(list, fmt.Errorf("%s%s: out of range", prefix, field))
		case "sample_bounds":
			list = append(list, fmt.Errorf(
				"%ssample_min: must be less than or equal to sample_max when sample_max > 0",
				prefix,
			))
		default:
			list = append(list, fmt.Errorf("%s%s: validation failed on %s", prefix, field, verr.Tag()))
		}
	}
	return errors.Join(list...)
}
