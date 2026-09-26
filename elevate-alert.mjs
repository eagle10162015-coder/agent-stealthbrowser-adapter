/**
 * Surface a security event to the human, immediately.
 *
 * Blocking an attack silently is only half the job — if the operator never
 * learns a page tried to open a port on their machine, they keep visiting it.
 * This escalates to the desktop the moment detection happens.
 *
 * Fire-and-forget by design: the alert is spawned detached and its failure can
 * never break the tool call that triggered it.
 */
import { spawn } from 'node:child_process';

/**
 * PowerShell toast via the WinRT API. Available on Windows 10/11 without
 * installing anything, unlike BurntToast which would be an extra dependency.
 */
function toastScript(title, body) {
  const escape = (s) => String(s).replace(/[&<>'"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&apos;', '"': '&quot;' }[c]));

  // Silent and non-urgent on purpose. The first version used
  // scenario="urgent" with a looping alarm, which meant a persistent on-screen
  // popup and a repeating sound the operator could not dismiss from the toast
  // itself. An alert that has to be chased away is worse than no alert — it
  // gets muted, and then real ones are missed too. The evidence path is written
  // into the body so the detail is readable without clicking anything.
  return `
$ErrorActionPreference = 'Stop'
try {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
  $xml.LoadXml(@"
<toast activationType="protocol" launch="file:///${process.env.USERPROFILE?.replace(/\\/g, '/')}/.llm-browser/incident-reports">
  <visual><binding template="ToastGeneric">
    <text>${escape(title)}</text>
    <text>${escape(body)}</text>
  </binding></visual>
  <audio silent="true"/>
</toast>
"@)
  $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LLM Security Guard').Show($toast)
} catch {
  # No interactive desktop (service, SSH). Log it rather than popping a blocking
  # msg.exe dialog, which would be another window demanding to be dismissed.
  Write-EventLog -LogName Application -Source LLMSecurityGuard -EventId 9002 \`
    -EntryType Warning -Message "${escape(title)} - ${escape(body)}" -ErrorAction SilentlyContinue
}`;
}

/**
 * Escalate a security event to the operator's desktop.
 *
 * @param {string} title  Short headline.
 * @param {string} body   One or two lines of detail.
 */
export function elevateToUser(title, body) {
  try {
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', toastScript(title, body)],
      { detached: true, stdio: 'ignore', windowsHide: true }
    );
    child.unref();
    return true;
  } catch {
    return false;
  }
}

/**
 * Turn a guard verdict into an operator-facing alert.
 *
 * Only genuine attacks escalate. Framing-only hits are common on ordinary
 * pages, and alerting on those would train the user to dismiss the popup —
 * which costs more than it gains.
 */
export function elevateScanResult(toolName, scanResult) {
  const categories = [...new Set(scanResult.signals.map((s) => s.category))];
  const capabilities = categories.filter((c) => c.startsWith('capability/'));
  if (!capabilities.length) return false;

  const what = capabilities.map((c) => c.replace('capability/', '')).join(', ');
  return elevateToUser(
    `Blocked a prompt-injection attack (${scanResult.severity})`,
    `A page tried to make the agent: ${what}. Blocked via ${toolName}. ` +
      `Evidence saved to .llm-browser\\incident-reports.`
  );
}
