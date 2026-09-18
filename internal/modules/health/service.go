package health

// Service defines the interface for health and readiness checks.
type Service interface {
	CheckHealth() HealthData
	CheckReady() ReadyData
}

// HealthData represents the payload returned by the /health endpoint.
type HealthData struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// ReadyData represents the payload returned by the /ready endpoint.
type ReadyData struct {
	Status       string   `json:"status"`
	Dependencies []string `json:"dependencies"`
}

type healthService struct{}

// NewService constructs a new health service.
func NewService() Service {
	return &healthService{}
}

func (s *healthService) CheckHealth() HealthData {
	return HealthData{
		Status:  "ok",
		Service: "trustdocs-api",
	}
}

func (s *healthService) CheckReady() ReadyData {
	return ReadyData{
		Status:       "ready",
		Dependencies: make([]string, 0),
	}
}
