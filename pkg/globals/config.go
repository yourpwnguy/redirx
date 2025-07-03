package globals

type Config struct {
	URLS        []string
	URLSList    string
	MatchCodes  []int
	VulnOnly    bool
	Concurrency int64
	PayloadList string
}
