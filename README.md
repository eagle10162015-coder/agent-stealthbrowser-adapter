# Agent StealthBrowser adapter

This is a headed, persistent CloakBrowser MCP adapter for an LLM agent and a
human using the same browser window. It uses the shared Wraith account vault
for imported accounts. Account lookup returns labels and IDs. `llm_autofill`
and `llm_fill_account` place a chosen password into the live page without
returning it in an MCP result.

## Setup

1. Install Node.js 22+, Python 3.10+, this package, and the Wraith fork.
2. Import each Google Password Manager export into the encrypted local vault:

   ```powershell
   python -m wraith.account_vault import-google C:\path\to\passwords.csv --source personal-google
   ```

3. Start the MCP server with `node llm-browser-mcp.mjs`. It uses a persistent
   `default` profile at `~/.cloakbrowser/google-profile` unless you choose a
   named profile. Headed mode is the default. Set `WRAITH_PYTHON` if Python is
   not on PATH.

The MCP tools can list accounts, fill a selected account, save a newly created
or rotated password, delete an account, and import additional CSV files. The
agent gets website content via structured actions; screenshots remain an
optional tool rather than the login path.
When changing a password, pass the existing `account_id` to
`llm_credential_save` so the imported Google record is updated in place.

The adapter source is Apache-2.0 licensed. It depends on CloakBrowser's MIT
wrapper. CloakHQ applies separate terms to its compiled Chromium binary;
this repository neither includes nor relicenses that binary. See
[CloakBrowser's binary license](https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md).

Site acceptance and challenge results vary. The code should report a blocked
or interrupted login rather than treating an attempted fill as success.
