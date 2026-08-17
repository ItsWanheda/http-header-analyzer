package models

import "time"

type AnalysisResult struct {
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`

	SecurityHeaders []SecurityHeader `json:"security_headers"`
	TLS             TLSInfo          `json:"tls"`
	Redirects       []RedirectInfo    `json:"redirects"`

	Score  int    `json:"score"`
	Rating string `json:"rating"`

	Issues []Issue `json:"issues"`

	// Advanced analysis
	HSTS              HSTSAnalysis           `json:"hsts"`
	SecurityTxt       SecurityTxtAnalysis    `json:"security_txt"`
	Technologies      TechnologyDetection    `json:"technologies"`
	InformationLeaks  []InformationDisclosure `json:"information_disclosure"`
	HTTPMethods       HTTPMethodsAnalysis    `json:"http_methods"`
	CORS              CORSAnalysis           `json:"cors"`
}