package engine

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// NotifyDesktop posts a system notification when, under GitHub Desktop, a
// hook after a pull, merge, rebase or branch switch finds secrets that
// need the user: Desktop shows nothing those hooks say, and the next
// commit may be a while off. Each problem is notified once. enc.notify
// false turns it off.
func (e *Engine) NotifyDesktop(what string) {
	if !e.Desktop() || !e.Repo.ConfigBool("enc.notify", true) {
		return
	}
	var items []note
	for _, s := range e.Secrets {
		switch s.Kind {
		case Outdated, Missing, Conflict, Diverged, Merging, NoKey, Corrupt:
			if !s.Skipped {
				items = append(items, note{Key: s.Path + "|" + string(s.Kind) + "|" + s.EncBlob, Path: s.Path, Text: shortState(s), Hint: s.Action})
			}
		}
	}
	for _, s := range e.rolledBack {
		items = append(items, note{Key: "rollback|" + s.Path + "|" + s.EncBlob, Path: s.Path,
			Text: "went back to an earlier value; if nobody meant that, it was rolled back", Hint: "git log -- " + s.EncPath})
	}
	d := e.loadDesktop()
	done := map[string]bool{}
	for _, k := range d.Notified {
		done[k] = true
	}
	var fresh []note
	for _, n := range items {
		if !done[n.Key] {
			fresh = append(fresh, n)
			d.Notified = append(d.Notified, n.Key)
		}
	}
	if len(fresh) == 0 {
		return
	}
	var body string
	if len(fresh) == 1 {
		n := fresh[0]
		body = n.Path + ": " + n.Text + "."
		if n.Hint != "" {
			body += " In a terminal: " + n.Hint
		}
	} else {
		var paths []string
		for _, n := range fresh {
			paths = append(paths, n.Path)
		}
		body = fmt.Sprintf("%s need you after the %s: %s. In a terminal: git enc status", plural(len(fresh), "secret"), what, list(paths))
	}
	notify("git-enc", body)
	e.saveDesktop(d)
}

// notify posts a system notification with the tools each system has, and
// never waits for it or fails: it is only a courtesy. The notifier gets
// none of the hook's output streams, which Desktop waits on to close.
func notify(title, body string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		cmd = exec.Command("osascript", "-e", "display notification "+q(body)+" with title "+q(title))
	case "windows":
		x := func(s string) string {
			return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "''").Replace(s)
		}
		script := `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('<toast><visual><binding template="ToastGeneric"><text>` + x(title) + `</text><text>` + x(body) + `</text></binding></visual></toast>')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))`
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	default:
		if _, err := exec.LookPath("notify-send"); err != nil {
			return
		}
		cmd = exec.Command("notify-send", title, body)
	}
	// Not in the repository: on Windows a notifier still running there would
	// keep the folder from being moved or deleted.
	cmd.Dir = os.TempDir()
	if cmd.Start() == nil {
		cmd.Process.Release()
	}
}
