package models

// HSTSAnalysis contains detailed HSTS configuration information.
type HSTSAnalysis struct {
	Present           bool   `json:"present"`
	Value             string `json:"value"`
	MaxAge            int64  `json:"max_age"`
	IncludeSubDomains bool   `json:"include_subdomains"`
	Preload           bool   `json:"preload"`
	Strong            bool   `json:"strong"`
	Status            string `json:"status"`
	Message           string `json:"message"`
}

// SecurityTxtAnalysis contains /.well-known/security.txt information.
type SecurityTxtAnalysis struct {
	Found       bool     `json:"found"`
	Valid       bool     `json:"valid"`
	URL         string   `json:"url"`
	Expires     string   `json:"expires,omitempty"`
	Contact     []string `json:"contact,omitempty"`
	Policy      []string `json:"policy,omitempty"`
	Acknowledgments []string `json:"acknowledgments,omitempty"`
	Encryption  []string `json:"encryption,omitempty"`
	Message     string   `json:"message"`
}

// Technology represents detected technology.
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence int      `json:"confidence"`
}

// TechnologyDetection contains detected technologies.
type TechnologyDetection struct {
	Technologies []Technology `json:"technologies"`
}

// InformationDisclosure represents an information disclosure finding.
type InformationDisclosure struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Value    string `json:"value"`
	Header   string `json:"header,omitempty"`
	Message  string `json:"message"`
}

// HTTPMethodsAnalysis contains supported HTTP methods.
type HTTPMethodsAnalysis struct {
	Methods       []string `json:"methods"`
	Dangerous     []string `json:"dangerous"`
	Unexpected    []string `json:"unexpected"`
	TraceEnabled  bool     `json:"trace_enabled"`
	PutEnabled    bool     `json:"put_enabled"`
	DeleteEnabled bool     `json:"delete_enabled"`
	Status        string   `json:"status"`
	Message       string   `json:"message"`
}

// CORSAnalysis contains CORS configuration.
type CORSAnalysis struct {
	Present          bool     `json:"present"`
	AllowOrigin      string   `json:"allow_origin"`
	AllowMethods     []string `json:"allow_methods,omitempty"`
	AllowHeaders     []string `json:"allow_headers,omitempty"`
	AllowCredentials bool     `json:"allow_credentials"`
	ExposedHeaders   []string `json:"exposed_headers,omitempty"`
	MaxAge           string   `json:"max_age,omitempty"`
	Dangerous        bool     `json:"dangerous"`
	Status           string   `json:"status"`
	Message          string   `json:"message"`
}