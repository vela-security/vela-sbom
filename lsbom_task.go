package sbom

import (
	"github.com/vela-security/vela-sbom/detect"
	"github.com/vela-security/vela-sbom/detect/artifact"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/detect/source"
)

type Task struct {
	name   string
	handle func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)
	err    error
}

func Tasks(opt *Option) ([]*Task, error) {
	var tasks []*Task

	generators := []func(opt *Option) (*Task, error){
		generateCatalogPackagesTask,
	}

	for _, generator := range generators {
		task, err := generator(opt)
		if err != nil {
			return nil, err
		}

		if task != nil {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

func generateCatalogPackagesTask(opt *Option) (*Task, error) {
	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		packageCatalog, relationships, theDistro, err := detect.CatalogPackages(src, opt.Cataloger)
		if err != nil {
			return nil, err
		}

		results.PackageCatalog = packageCatalog
		results.LinuxDistribution = theDistro

		return relationships, nil
	}

	return &Task{name: "packages", handle: task}, nil
}

func (t *Task) run(result *sbom.Artifacts, src *source.Source) []artifact.Relationship {
	r, e := t.handle(result, src)
	t.err = e
	return r
}
