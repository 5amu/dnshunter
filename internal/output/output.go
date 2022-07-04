package output

type CheckOutput struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
	Vulnerable  bool     `json:"vulnerable"`
	Message     string   `json:"message"`
}

func (o *CheckOutput) String() string {
	return ""
}
