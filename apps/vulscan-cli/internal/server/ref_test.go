package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGitRefAcceptsVersions(t *testing.T) {
	for _, ref := range []string{"v1.2.0", "release/1.x", "abc1234", "a1b2c3d4e5f6", "fix_typo", ""} {
		got, err := validateGitRef("  " + ref + "  ")
		if err != nil {
			t.Fatalf("%q rejected: %v", ref, err)
		}
		if got != strings.TrimSpace(ref) {
			t.Fatalf("%q normalised to %q", ref, got)
		}
	}
}

func TestValidateGitRefRejectsDangerousShapes(t *testing.T) {
	cases := map[string]string{
		"-p":              "短横线",
		"--upload-pack=x": "短横线",
		"a..b":            "字符序列",
		"a@{1}":           "字符序列",
		"v1 0":            "只能包含",
		"$(id)":           "只能包含",
		"v1;rm":           "只能包含",
		strings.Repeat("a", 129): "过长",
	}
	for ref, want := range cases {
		_, err := validateGitRef(ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: want error containing %q, got %v", ref, want, err)
		}
	}
}

func TestLooksLikeCommitSHA(t *testing.T) {
	for _, ref := range []string{"abc1234", "0123456789abcdef0123456789abcdef01234567"} {
		if !looksLikeCommitSHA(ref) {
			t.Fatalf("%q should be treated as a commit", ref)
		}
	}
	for _, ref := range []string{"v1.2.0", "main", "abc123", "feature/abc1234", "xyz9999"} {
		if looksLikeCommitSHA(ref) {
			t.Fatalf("%q should be cloned by branch", ref)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepoWithTag(t *testing.T) (dir, tagCommit string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 不可用")
	}
	dir = t.TempDir()
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "symbolic-ref", "HEAD", "refs/heads/main")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0640); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-qm", "one")
	gitRun(t, dir, "tag", "v1.0.0")
	tagCommit = gitRun(t, dir, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("two\n"), 0640); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "commit", "-qam", "two")
	return dir, tagCommit
}

// The fallback path for a commit SHA (and for any ref --branch refused) is a
// plain clone followed by a detached checkout. This pins that behaviour.
func TestCheckoutRefDetachesAtTag(t *testing.T) {
	src, tagCommit := newRepoWithTag(t)
	dest := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", "--", src, dest).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if err := runGit(context.Background(), []string{"-C", dest, "checkout", "--detach", "v1.0.0"}, "checkout", func(string) {}); err != nil {
		t.Fatalf("checkout tag: %v", err)
	}
	if got := gitRun(t, dest, "rev-parse", "HEAD"); got != tagCommit {
		t.Fatalf("HEAD=%s want %s", got, tagCommit)
	}
	data, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || strings.TrimSpace(string(data)) != "one" {
		t.Fatalf("worktree not at tag: %q %v", data, err)
	}
}

func TestCheckoutRefReportsMissingVersion(t *testing.T) {
	src, _ := newRepoWithTag(t)
	dest := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", "--", src, dest).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	err := runGit(context.Background(), []string{"-C", dest, "checkout", "--detach", "v9.9.9"}, "checkout", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "无法检出该版本") {
		t.Fatalf("want a version-named error, got %v", err)
	}
}

func TestListRefsReturnsTagsBeforeBranches(t *testing.T) {
	src, _ := newRepoWithTag(t)
	gitRun(t, src, "branch", "feature-x")
	refs, err := listRefs(context.Background(), src)
	if err != nil {
		t.Fatalf("listRefs: %v", err)
	}
	if len(refs) < 2 {
		t.Fatalf("expected tag and branch, got %+v", refs)
	}
	if refs[0].Kind != "tag" || refs[0].Name != "v1.0.0" {
		t.Fatalf("tags must come first, got %+v", refs)
	}
	found := false
	for _, ref := range refs {
		if ref.Kind == "branch" && ref.Name == "feature-x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("branch missing from %+v", refs)
	}
}
