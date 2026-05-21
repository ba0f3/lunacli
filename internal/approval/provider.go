package approval

// Provider delivers pending approval notifications to a human-facing transport.
type Provider interface {
	Name() string
	Notify(pending PendingInfo, req ExecuteRemoteRequest) error
}

// ProviderSet fans out Notify to every configured provider.
type ProviderSet struct {
	providers []Provider
}

// NewProviderSet returns a set that calls providers in registration order.
func NewProviderSet(providers ...Provider) *ProviderSet {
	return &ProviderSet{providers: providers}
}

// NotifyAll invokes Notify on each provider; returns the first non-nil error, if any.
func (p *ProviderSet) NotifyAll(pending PendingInfo, req ExecuteRemoteRequest) error {
	var firstErr error
	for _, provider := range p.providers {
		if err := provider.Notify(pending, req); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
