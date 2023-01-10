package sbom

import (
	"context"
	"fmt"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/detect/source"
	"github.com/vela-security/vela-sbom/internal"
	"github.com/vela-security/vela-sbom/internal/anchore"
	"io/ioutil"
	"os"
)

func Scan(opt *Option) (*sbom.SBOM, error) {

	// could be an image or a directory, with or without a scheme
	si, err := source.ParseInput(opt.Filename, opt.Platform, true)
	if err != nil {
		return nil, fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	cause := catch.New()
	s := exec(opt, *si, cause)
	if cause.Len() > 0 {
		return nil, cause.Wrap()
	}
	return s, nil
}

func exec(opt *Option, si source.Input, cause *catch.Cause) *sbom.SBOM {
	src, cleanup, err := source.New(si, &opt.Registry, opt.Exclusions)
	if cleanup != nil {
		defer cleanup()
	}

	if err != nil {
		cause.Try("got source", err)
		return nil
	}

	s, err := GenerateSBOM(src, cause, opt)
	if err != nil {
		cause.Try("generate sbom", err)
		return nil
	}

	if s == nil {
		return nil
	}

	if opt.Anchore.Host != "" {
		if e := runPackageSbomUpload(src, *s, opt); e != nil {
			xEnv.Errorf("package sbom upload fail %v", e)
		}
	}

	return s

}

func GenerateSBOM(src *source.Source, cause *catch.Cause, opt *Option) (*sbom.SBOM, error) {
	tasks, err := Tasks(opt)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:          internal.ApplicationName,
			Version:       "v4.0",
			Configuration: opt,
		},
	}

	buildRelationships(&s, src, tasks, cause)

	return &s, nil
}

func buildRelationships(s *sbom.SBOM, src *source.Source, tasks []*Task, cause *catch.Cause) {
	for _, task := range tasks {
		v := task.run(&s.Artifacts, src)
		if task.err != nil {
			cause.Try(task.name, task.err)
			continue
		}
		s.Relationships = append(s.Relationships, v...)
	}
}

func runPackageSbomUpload(src *source.Source, s sbom.SBOM, opt *Option) error {
	xEnv.Infof("uploading results to %s", opt.Anchore.Host)

	if src.Metadata.Scheme != source.ImageScheme {
		return fmt.Errorf("unable to upload results: only images are supported")
	}

	var dockerfileContents []byte
	if opt.Anchore.Dockerfile != "" {
		if _, err := os.Stat(opt.Anchore.Dockerfile); os.IsNotExist(err) {
			return fmt.Errorf("unable dockerfile=%q does not exist: %w", opt.Anchore.Dockerfile, err)
		}

		fh, err := os.Open(opt.Anchore.Dockerfile)
		if err != nil {
			return fmt.Errorf("unable to open dockerfile=%q: %w", opt.Anchore.Dockerfile, err)
		}

		dockerfileContents, err = ioutil.ReadAll(fh)
		if err != nil {
			return fmt.Errorf("unable to read dockerfile=%q: %w", opt.Anchore.Dockerfile, err)
		}
	}

	c, err := anchore.NewClient(anchore.Configuration{
		BaseURL:  opt.Anchore.Host,
		Username: opt.Anchore.Username,
		Password: opt.Anchore.Password,
	})

	if err != nil {
		return fmt.Errorf("failed to create anchore client: %w", err)
	}

	importCfg := anchore.ImportConfig{
		ImageMetadata:           src.Image.Metadata,
		SBOM:                    s,
		Dockerfile:              dockerfileContents,
		OverwriteExistingUpload: opt.Anchore.OverwriteExistingImage,
		Timeout:                 opt.Anchore.ImportTimeout,
	}

	if err := c.Import(context.Background(), importCfg); err != nil {
		return fmt.Errorf("failed to upload results to host=%s: %+v", opt.Anchore.Host, err)
	}

	return nil
}
