package output

import "fmt"

type CheckOutput struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
	Vulnerable  bool     `json:"vulnerable"`
	Message     string   `json:"message"`
}

func (o *CheckOutput) String() string {
	// TODO: make colored output
	s := "[!] Check: %v - vulnerable: %v\n"
	s += "%v\n"
	return fmt.Sprintf(s, o.Name, o.Vulnerable, o.Message)
}
