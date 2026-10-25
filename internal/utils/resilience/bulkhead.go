package resilience

type Bulkhead struct {
	sem chan struct{}
}

func NewBulkhead(maxConcurrent int) *Bulkhead {
	return &Bulkhead{
		sem: make(chan struct{}, maxConcurrent),
	}
}

func (b *Bulkhead) Execute(fn func() error) error {
	b.sem <- struct{}{} // acquire slot
	defer func() { <-b.sem }()

	return fn()
}
