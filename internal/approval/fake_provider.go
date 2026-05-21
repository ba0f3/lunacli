package approval

// FakeProvider is a no-op notification provider that records decisions via Service for tests.
type FakeProvider struct {
	svc      *Service
	name     string
	approver string
}

// NewFakeProvider returns a provider named name that uses svc for Approve/Deny decisions.
// Default approver label is "test-human" when Approve/Deny get an empty approver string.
func NewFakeProvider(svc *Service, name string) *FakeProvider {
	return &FakeProvider{svc: svc, name: name, approver: "test-human"}
}

func (f *FakeProvider) Name() string { return f.name }

func (f *FakeProvider) Notify(PendingInfo, ExecuteRemoteRequest) error { return nil }

func (f *FakeProvider) Approve(id string, approver string) error {
	if approver == "" {
		approver = f.approver
	}
	return f.svc.Approve(id, approver, f.name)
}

func (f *FakeProvider) Deny(id string, approver string) error {
	if approver == "" {
		approver = f.approver
	}
	return f.svc.Deny(id, approver, f.name)
}
