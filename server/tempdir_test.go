package server

// Windows 友好的测试临时目录。
//
// t.TempDir() 的清理是同步的 os.RemoveAll：后台写手（SQLite WAL 刷盘、mitmproxy
// 收尾、归档协程）只要在枚举与删除之间碰一下目录，Windows 就会报
// "The directory is not empty" 并把整个用例判失败——断言其实早就通过了。
//
// tempDir 在清理时带退避重试：绝大多数情况 50–200ms 内句柄就释放了；重试到头
// 仍失败才 t.Errorf（不吞错，真泄漏照样红）。

import (
	"os"
	"testing"
	"time"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pojun-test-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		var last error
		// 30 秒而非 1 秒：一份 nuclei 模板树有 1.4 万个文件，Windows 上
		// RemoveAll 本身就要数秒，异步写手也需要时间退场。
		for i := 0; i < 120; i++ {
			if last = os.RemoveAll(dir); last == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		if last != nil {
			t.Errorf("cleanup temp dir %s: %v", dir, last)
		}
	})
	return dir
}
