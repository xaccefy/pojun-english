package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/chu0119/pojun/db"
)

// modelPrice is the built-in reference price (USD / 1M tokens). Pricing can only be
// approximate: vendors change prices per version/channel; these are public list-price
// magnitudes to show users the relative distribution of 'which task, which profile is
// burning money' — no billing accuracy promised. Prefix matching in declaration order
// (specific first, free at the very front so ':free' models aren't billed as paid).
type modelPrice struct {
	prefix string
	in     float64
	out    float64
}

var modelPrices = []modelPrice{
	{"free", 0, 0},
	{"claude-opus", 15, 75},
	{"claude-sonnet", 3, 15},
	{"claude-haiku", 0.8, 4},
	{"gpt-4o", 2.5, 10},
	{"gpt-4.1", 2, 8},
	{"gpt-5", 1.25, 10},
	{"o3", 2, 8},
	{"gemini-2.5-pro", 1.25, 10},
	{"gemini-2.5-flash", 0.3, 2.5},
	{"deepseek", 0.27, 1.1},
	{"glm", 0.6, 2},
	{"qwen", 0.4, 1.2},
	{"kimi", 0.6, 2.5},
	{"nemotron", 0, 0},
	{"llama", 0.2, 0.6},
}

// estimateUSDCost estimates one usage's cost by model name; known=false means the model
// isn't in the price table — cost counts as 0 and the caller must surface the model name
// to the user (never silently mis-bill).
func estimateUSDCost(model string, inTok, outTok int) (usd float64, known bool) {
	m := strings.ToLower(model)
	for _, p := range modelPrices {
		if strings.Contains(m, p.prefix) {
			return (float64(inTok)*p.in + float64(outTok)*p.out) / 1e6, true
		}
	}
	return 0, false
}

// profileCost is the per-profile aggregated cost view.
type profileCost struct {
	ProfileName  string  `json:"profile_name"`
	Calls        int     `json:"calls"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// pgUsageCost returns the cost estimate. ?task=<id> returns that task (priced per
// model); otherwise the whole site aggregated by profile + totals. All amounts are
// 'built-in reference-price estimates'; the response carries unpriced_models verbatim so
// the frontend can flag which models can't be priced (instead of counting them as free).
func (s *Server) pgUsageCost(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, map[string]any{"total_cost_usd": 0})
		return
	}
	if task := strings.TrimSpace(r.URL.Query().Get("task")); task != "" {
		rows, err := pg.UsageModelsByTask(task)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		var total db.TaskUsage
		total.TaskID = task
		var cost float64
		unpriced := map[string]bool{}
		for _, row := range rows {
			c, known := estimateUSDCost(row.Model, row.InputTokens, row.OutputTokens)
			cost += c
			if !known {
				unpriced[row.Model] = true
			}
			total.Calls += row.Calls
			total.InputTokens += row.InputTokens
			total.OutputTokens += row.OutputTokens
		}
		writeJSON(w, 200, map[string]any{
			"task":            total,
			"cost_usd":        round4(cost),
			"unpriced_models": keysOf(unpriced),
			"pricing_note":    "Estimated at built-in reference prices (USD per million tokens) — for relative comparison only, no billing accuracy promised; archived tasks excluded.",
		})
		return
	}

	rows, err := pg.UsageByModel()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	byProfile := map[string]*profileCost{}
	var totalIn, totalOut int
	var totalCost float64
	unpriced := map[string]bool{}
	for _, row := range rows {
		c, known := estimateUSDCost(row.Model, row.InputTokens, row.OutputTokens)
		if !known {
			unpriced[row.Model] = true
		}
		p := byProfile[row.ProfileName]
		if p == nil {
			p = &profileCost{ProfileName: row.ProfileName}
			byProfile[row.ProfileName] = p
		}
		p.Calls += row.Calls
		p.InputTokens += row.InputTokens
		p.OutputTokens += row.OutputTokens
		p.CostUSD += c
		totalIn += row.InputTokens
		totalOut += row.OutputTokens
		totalCost += c
	}
	out := make([]profileCost, 0, len(byProfile))
	for _, p := range byProfile {
		p.CostUSD = round4(p.CostUSD)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	writeJSON(w, 200, map[string]any{
		"total": map[string]any{
			"input_tokens":  totalIn,
			"output_tokens": totalOut,
			"cost_usd":      round4(totalCost),
		},
		"by_profile":      out,
		"unpriced_models": keysOf(unpriced),
		"pricing_note":    "Estimated at built-in reference prices (USD per million tokens) — for relative comparison only, no billing accuracy promised; archived tasks excluded.",
	})
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
