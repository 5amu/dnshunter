package output

import (
	"fmt"

	"github.com/5amu/dnshunter/internal/common"
)

type CheckOutput struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Nameservers []string `json:"nameservers"`
	Vulnerable  bool     `json:"vulnerable"`
	Message     string   `json:"message"`
}

func (o *CheckOutput) String() string {
	s := common.Header(fmt.Sprintf("Check: %v - vulnerable: %v", o.Name, o.Vulnerable))
	s += o.Message
	return s
}
