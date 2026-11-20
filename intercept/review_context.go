package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const reviewTextLimit = 4000

const BackgroundUserMessage = "user_message"

// ReviewBackground is explicitly bound from the current human message. Generated
// Worker summaries are not accepted. Background cannot override review policy.
type ReviewBackground struct {
	Source    string `json:"source"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ReviewInput contains only the current call and explicitly selected background.
// Execution history and call correlation belong to the separate audit record.
type ReviewInput struct {
	Version    int               `json:"version"`
	WorkingDir string            `json:"working_directory,omitempty"`
	Background *ReviewBackground `json:"background,omitempty"`
	Tool       string            `json:"tool_name"`
	Arguments  json.RawMessage   `json:"arguments"`
	// Scripts 是 issue #21.2 的本地脚本正文快照：命令行只写 `python3 exp.py`
	// 时，正则与 Judge 只能看到文件名。这里把引用到的静态脚本文件读出来
	// 附上（数量/总量受限、只读普通文件），让「先落盘再执行」的载荷对
	// 审查层可见。动态路径（含变量/通配）进 UnresolvedScripts，由 Judge
	// 按「内容不可见」的保守口径处理。
	Scripts           []ReviewScript `json:"scripts,omitempty"`
	UnresolvedScripts []string       `json:"unresolved_scripts,omitempty"`
}

// ReviewScript 是一个被当前调用引用的本地脚本文件的正文快照。
type ReviewScript struct {
	Path      string `json:"path"`
	Body      string `json:"body"`
	Truncated bool   `json:"truncated,omitempty"`
}

// 脚本快照限额：审查输入不能被超大脚本撑爆（Judge 的上下文与规则匹配都要过它）。
const (
	reviewScriptMaxFiles   = 4
	reviewScriptMaxPerFile = 32 << 10 // 32KB per file
	reviewScriptMaxTotal   = 128 << 10
)

// reviewInterpreters 是「紧跟解释器名的第一个非选项参数 ≈ 脚本路径」的解释器清单。
var reviewInterpreters = map[string]bool{
	"python": true, "python3": true, "bash": true, "sh": true,
	"node": true, "php": true, "perl": true, "ruby": true,
}

// reviewScriptExts 是无需解释器前缀也算脚本引用的扩展名（./x.sh、scripts/foo.py）。
var reviewScriptExts = map[string]bool{
	".py": true, ".sh": true, ".js": true, ".mjs": true, ".cjs": true,
	".php": true, ".pl": true, ".rb": true, ".ps1": true,
}

type reviewContextKey struct{}
type reviewEnvironment struct {
	workingDir string
	background ReviewBackground
}

// WithReviewContext explicitly binds the permitted background for one run. Never
// fall back to the raw turn transcript: it may contain the full scheduler prompt.
// This is application wiring, not a model-callable tool.
func WithReviewContext(ctx context.Context, workingDir string, background ReviewBackground) context.Context {
	return context.WithValue(ctx, reviewContextKey{}, reviewEnvironment{workingDir, background})
}

// WithReviewWorkingDirectory preserves only explicitly selected background.
// Chat runs can be human-initiated or scheduled, so the Agent must not infer
// message provenance from the text it receives.
func WithReviewWorkingDirectory(ctx context.Context, workingDir string) context.Context {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	env.workingDir = workingDir
	return context.WithValue(ctx, reviewContextKey{}, env)
}

// ReviewWorkingDirectory returns the working directory bound to this run, or
// "" when none is bound.
//
// Purpose: tools need to write scripts/intermediate artifacts into 'this run's working
// directory' (platform convention keeps intermediates out of /tmp), but the tool itself
// can't see the run's directory — it only sees call parameters in its own context. This
// reader is the sole outlet for that directory.
func ReviewWorkingDirectory(ctx context.Context) string {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	return env.workingDir
}

func BuildReviewInput(ctx context.Context, tool string, arguments json.RawMessage) (ReviewInput, error) {
	if !json.Valid(arguments) {
		return ReviewInput{}, fmt.Errorf("tool parameters are not valid JSON")
	}
	in := ReviewInput{Version: 5, Tool: tool, Arguments: append(json.RawMessage(nil), arguments...)}
	if env, ok := ctx.Value(reviewContextKey{}).(reviewEnvironment); ok {
		in.WorkingDir = env.workingDir
		background := env.background
		if background.Source == BackgroundUserMessage && strings.TrimSpace(background.Text) != "" {
			var cut bool
			background.Text, cut = bounded(background.Text, reviewTextLimit)
			background.Truncated = background.Truncated || cut
			in.Background = &background
		}
	}
	in.attachScripts()
	return in, nil
}

// attachScripts 从工具参数里的 shell 命令提取被引用的本地脚本文件，读取正文
// 快照（issue #21.2）。只做静态提取：解释器后面的第一个非选项参数、以及任何
// 带脚本扩展名的 token。含变量/通配的路径记 UnresolvedScripts，不猜值。
func (in *ReviewInput) attachScripts() {
	var total int
	seen := map[string]bool{}
	full := false
	for _, cmd := range reviewCommandCandidates(in.Arguments) {
		for _, p := range scriptPathsInCommand(cmd) {
			if full || seen[p] {
				continue
			}
			seen[p] = true
			if len(in.Scripts) >= reviewScriptMaxFiles {
				full = true
				continue
			}
			if isDynamicScriptPath(p) {
				in.UnresolvedScripts = append(in.UnresolvedScripts, p)
				continue
			}
			path := p
			if !filepath.IsAbs(path) && in.WorkingDir != "" {
				path = filepath.Join(in.WorkingDir, path)
			}
			// 只读普通文件：设备/命名管道（/dev/zero、fifo）会让 PreToolUse
			// 挂死——读之前必须先 stat（agent/tools_diff.go 的同一课）。
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() {
				in.UnresolvedScripts = append(in.UnresolvedScripts, p)
				continue
			}
			sz := st.Size()
			if sz > reviewScriptMaxPerFile || total+int(sz) > reviewScriptMaxTotal {
				in.UnresolvedScripts = append(in.UnresolvedScripts, p+" (over the snapshot limit)")
				continue
			}
			body, err := os.ReadFile(path)
			if err != nil {
				in.UnresolvedScripts = append(in.UnresolvedScripts, p)
				continue
			}
			total += len(body)
			b := string(body)
			truncated := false
			if len(b) > reviewScriptMaxPerFile {
				b = b[:reviewScriptMaxPerFile]
				truncated = true
			}
			in.Scripts = append(in.Scripts, ReviewScript{Path: p, Body: b, Truncated: truncated})
		}
	}
}

// reviewCommandCandidates 从工具参数 JSON 里取 shell 命令字段：Bash/shell_open
// 的 command、shell_send 的 text、job_start 的 command。字段不存在时返回空。
func reviewCommandCandidates(arguments json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &obj); err != nil {
		return nil
	}
	var out []string
	for _, key := range []string{"command", "text"} {
		if raw, ok := obj[key]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// scriptPathsInCommand 提取命令行里引用的脚本路径 token。按 ; | && || 换行切段
// 后逐 token 看：解释器名后的第一个非选项参数、或任何带脚本扩展名的 token。
func scriptPathsInCommand(cmd string) []string {
	var out []string
	segments := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '|' || r == '\n' || r == '&'
	})
	for _, seg := range segments {
		toks := strings.Fields(seg)
		expect := false
		for _, tok := range toks {
			base := tok
			if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
				base = base[i+1:]
			}
			switch {
			case expect && !strings.HasPrefix(tok, "-"):
				out = append(out, strings.Trim(tok, `"'`))
				expect = false
			case reviewInterpreters[base]:
				expect = true
			case reviewScriptExts[strings.ToLower(filepath.Ext(base))]:
				out = append(out, strings.Trim(tok, `"'`))
			}
		}
	}
	return out
}

// isDynamicScriptPath 报告路径里含无法静态解析的部分（变量、命令替换、通配、
// 花括号展开）。这类路径不猜值，交 Judge 按「内容不可见」保守处理。
func isDynamicScriptPath(p string) bool {
	return strings.ContainsAny(p, "$`*?{")
}
