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
	s := "=> Check: %v / Vulnerable: %v\n"
	s += "====> domain: %v\n"
	s += "====> nameservers: %v\n%v"
	return fmt.Sprintf(s, o.Name, o.Vulnerable, o.Domain, o.Nameservers, o.Message)
}
