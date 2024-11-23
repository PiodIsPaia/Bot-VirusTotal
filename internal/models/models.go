package models

type VirusTotalResponse struct {
	ResponseCode int `json:"response_code"`
	Positives    int `json:"positives"`
	Total        int `json:"total"`
	Scans        map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
	} `json:"scans"`
}
