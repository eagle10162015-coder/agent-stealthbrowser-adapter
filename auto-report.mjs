/**
 * File a quarantined attack automatically (SEC-03, SEC-04a).
 *
 * The user's instruction was explicit: a detected attack must be detected,
 * flat-out ignored, and reported automatically — not queued behind a
 * permission prompt. Detection and ignoring were already wired at the browser
 * MCP's serialization chokepoint, but nothing ever invoked the reporter:
 * `incident_reporter.py` was referenced by no file except itself, so every
 * incident sat in quarantine.jsonl unfiled.
 *
 * Two sinks, because they fail in different situations:
 *   - `incident_reporter.py` files the durable record (Windows Event Log, and
 *     a pre-filled IC3 packet for human review). It is the evidence trail.
 *   - the shared notify library reaches the operator wherever they are, via
 *     ntfy phone push. This is what makes reporting non-inert without SMTP:
 *     the CISA email path stays gated on GUARD_SMTP_HOST, but the operator is
 *     told regardless.
 *
 * Everything here is fire-and-forget. A reporting failure must never break, or
 * even slow, the tool call that triggered it — the attack is already blocked by
 * the time this runs.
 */
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const REPORTER = join(homedir(), 'llm-agents', 'incident_reporter.py');
const NOTIFY_LIB = join(homedir(), 'llm-agents', 'notify', 'notify.mjs');
const FAILURE_LOG = join(homedir(), '.llm-browser', 'auto-report-errors.log');

/**
 * A poisoned page usually trips several signals in one payload, and a crawl can
 * hit the same page repeatedly. Filing is deduped downstream by the reporter,
 * but spawning a Python process per signal would still stall the browser, so
 * bursts collapse into one filing.
 */
const DEBOUNCE_MS = 60000;
// -Infinity, not 0: the first attack must always be filed. Seeding with 0 makes
// that depend on the clock's origin being far from zero — true of Date.now(),
// false of any injected or monotonic clock — so the very first incident after
// startup could be silently swallowed as if it were a duplicate.
let lastFiledAt = -Infinity;

function note(message) {
  try {
    appendFileSync(FAILURE_LOG, `${new Date().toISOString()} ${message}\n`);
  } catch {
    // Nothing left to fall back to; losing this line must not raise.
  }
}

/** Runs the reporter over anything not yet filed. Detached so it outlives this call. */
function fileIncident() {
  try {
    const child = spawn('python', [REPORTER], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.on('error', (error) => note(`reporter spawn failed: ${error.message}`));
    child.unref();
    return true;
  } catch (error) {
    note(`reporter spawn threw: ${error.message}`);
    return false;
  }
}

/** Pushes the alert to the operator's desktop and phone. */
async function pushAlert(toolName, scanResult, capabilities) {
  try {
    const lib = await import(`file:///${NOTIFY_LIB.replace(/\\/g, '/')}`);
    await lib.notify(
      `Blocked a prompt-injection attack (${scanResult.severity})`,
      `A page tried to make the agent: ${capabilities.join(', ')}. Blocked via ${toolName}. `
        + 'Filed to the Windows Event Log; IC3 packet staged for your review.',
      'failed',
      'security-guard',
      join(homedir(), '.llm-browser', 'incident-reports'),
    );
    return true;
  } catch (error) {
    note(`notify failed: ${error.message}`);
    return false;
  }
}

/**
 * Reports a scan verdict, if it warrants reporting.
 *
 * Only capability-class attacks — a page trying to make the agent open a port,
 * exfiltrate, or execute — are filed and pushed. Framing-only hits appear on
 * ordinary pages, and filing those would bury the real ones and train the
 * operator to ignore the alert.
 */
export function autoReport(toolName, scanResult, now = () => Date.now()) {
  const capabilities = [...new Set(
    (scanResult?.signals ?? [])
      .map((signal) => signal.category ?? '')
      .filter((category) => category.startsWith('capability/'))
      .map((category) => category.replace('capability/', '')),
  )];

  if (capabilities.length === 0) return { filed: false, reason: 'framing-only' };

  const stamp = now();
  if (stamp - lastFiledAt < DEBOUNCE_MS) {
    return { filed: false, reason: 'debounced', capabilities };
  }
  lastFiledAt = stamp;

  const filed = fileIncident();
  void pushAlert(toolName, scanResult, capabilities);
  return { filed, reason: filed ? 'filed' : 'reporter-unavailable', capabilities };
}

/** Exposed so the debounce can be exercised deterministically in tests. */
export function _resetDebounce() {
  lastFiledAt = -Infinity;
}
