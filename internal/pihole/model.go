package pihole

type QueryStats struct {
	Queries         []Query `json:"queries"`
	Cursor          int     `json:"cursor"`
	RecordsTotal    int     `json:"recordsTotal"`
	RecordsFiltered int     `json:"recordsFiltered"`
	Draw            int     `json:"draw"`
	Took            float64 `json:"took"`
}

type Query struct {
	ID       int         `json:"id"`
	Time     float64     `json:"time"`
	Type     string      `json:"type"`
	Status   string      `json:"status"`
	DNSSEC   string      `json:"dnssec"`
	Domain   string      `json:"domain"`
	Upstream *string     `json:"upstream"`
	Reply    QueryReply  `json:"reply"`
	Client   QueryClient `json:"client"`
	ListID   *int        `json:"list_id"`
	EDE      QueryEDE    `json:"ede"`
	CNAME    *string     `json:"cname"`
}

type QueryReply struct {
	Type string  `json:"type"`
	Time float64 `json:"time"`
}

type QueryClient struct {
	IP   string  `json:"ip"`
	Name *string `json:"name"`
}

type QueryEDE struct {
	Code int     `json:"code"`
	Text *string `json:"text"`
}
