package diff

type processTree interface {
	Assign() error
	Kill() (effective bool, err error)
	Close() error
}

var processTreeFactory = newProcessTree
