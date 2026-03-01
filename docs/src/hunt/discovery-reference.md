# Discovery Reference

Platform-specific client paths, config file locations, and built-in tool definitions used by `hunt scan` during the discovery stage.

## Platform detection

The scanner selects client definitions based on the host operating system:

| OS | Detection | Client list |
|----|-----------|-------------|
| macOS | `std::env::consts::OS == "macos"` | `MACOS_WELL_KNOWN_CLIENTS` |
| Linux | `std::env::consts::OS == "linux"` | `LINUX_WELL_KNOWN_CLIENTS` |
| Windows | `std::env::consts::OS == "windows"` | `WINDOWS_WELL_KNOWN_CLIENTS` |

All paths use `~` as a prefix, expanded at runtime to the user's home directory.

A client is considered **present** if any path in its `client_exists_paths` exists on disk.

## Well-known clients

### macOS

| Client | Exists paths | MCP config paths | Skills dirs |
|--------|-------------|------------------|-------------|
| windsurf | `~/.codeium` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills` |
| cursor | `~/.cursor` | `~/.cursor/mcp.json` | `~/.cursor/skills` |
| vscode | `~/.vscode` | `~/Library/Application Support/Code/User/settings.json`, `~/Library/Application Support/Code/User/mcp.json` | `~/.copilot/skills` |
| claude | `~/Library/Application Support/Claude` | `~/Library/Application Support/Claude/claude_desktop_config.json` | -- |
| claude code | `~/.claude` | `~/.claude.json` | `~/.claude/skills` |
| gemini cli | `~/.gemini` | `~/.gemini/settings.json` | `~/.gemini/skills` |
| clawdbot | `~/.clawdbot` | -- | `~/.clawdbot/skills` |
| kiro | `~/.kiro` | `~/.kiro/settings/mcp.json` | -- |
| opencode | `~/.config/opencode` | -- | -- |
| antigravity | `~/.gemini/antigravity` | `~/.gemini/antigravity/mcp_config.json` | -- |
| codex | `~/.codex` | -- | `~/.codex/skills` |

### Linux

| Client | Exists paths | MCP config paths | Skills dirs |
|--------|-------------|------------------|-------------|
| windsurf | `~/.codeium` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills` |
| cursor | `~/.cursor` | `~/.cursor/mcp.json` | `~/.cursor/skills` |
| vscode | `~/.vscode`, `~/.config/Code` | `~/.config/Code/User/settings.json`, `~/.vscode/mcp.json`, `~/.config/Code/User/mcp.json` | `~/.copilot/skills` |
| claude code | `~/.claude` | `~/.claude.json` | `~/.claude/skills` |
| gemini cli | `~/.gemini` | `~/.gemini/settings.json` | `~/.gemini/skills` |
| openclaw | `~/.clawdbot`, `~/.openclaw` | -- | `~/.clawdbot/skills`, `~/.openclaw/skills` |
| kiro | `~/.kiro` | `~/.kiro/settings/mcp.json` | -- |
| opencode | `~/.config/opencode` | -- | -- |
| antigravity | `~/.gemini/antigravity` | `~/.gemini/antigravity/mcp_config.json` | -- |
| codex | `~/.codex` | -- | `~/.codex/skills` |

Notable differences from macOS: no Claude Desktop client; `clawdbot` becomes `openclaw` with additional `~/.openclaw` paths; VS Code uses XDG paths (`~/.config/Code`).

### Windows

| Client | Exists paths | MCP config paths | Skills dirs |
|--------|-------------|------------------|-------------|
| windsurf | `~/.codeium` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills` |
| cursor | `~/.cursor` | `~/.cursor/mcp.json` | `~/.cursor/skills` |
| vscode | `~/.vscode`, `~/.config/Code` | `~/.config/Code/User/settings.json`, `~/.vscode/mcp.json`, `~/.config/Code/User/mcp.json` | `~/.copilot/skills` |
| claude | `~/AppData/Roaming/Claude` | `~/AppData/Roaming/Claude/claude_desktop_config.json` | -- |
| claude code | `~/.claude` | `~/.claude.json` | `~/.claude/skills` |
| gemini cli | `~/.gemini` | `~/.gemini/settings.json` | `~/.gemini/skills` |
| openclaw | `~/.clawdbot`, `~/.openclaw` | -- | `~/.clawdbot/skills`, `~/.openclaw/skills` |
| kiro | `~/.kiro` | `~/.kiro/settings/mcp.json` | -- |
| opencode | `~/.config/opencode` | -- | -- |
| antigravity | `~/.gemini/antigravity` | `~/.gemini/antigravity/mcp_config.json` | -- |

Notable: no Codex on Windows. Claude Desktop uses `~/AppData/Roaming/Claude`.

## Client shorthand resolution

A separate shorthand lookup maps short names to config file paths for use with `--target`:

### macOS

| Shorthand | Config paths |
|-----------|-------------|
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| `cursor` | `~/.cursor/mcp.json` |
| `claude` | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| `vscode` | `~/.vscode/mcp.json`, `~/Library/Application Support/Code/User/settings.json`, `~/Library/Application Support/Code/User/mcp.json` |

### Linux

| Shorthand | Config paths |
|-----------|-------------|
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| `cursor` | `~/.cursor/mcp.json` |
| `vscode` | `~/.vscode/mcp.json`, `~/.config/Code/User/settings.json`, `~/.config/Code/User/mcp.json` |

### Windows

| Shorthand | Config paths |
|-----------|-------------|
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| `cursor` | `~/.cursor/mcp.json` |
| `claude` | `~/AppData/Roaming/Claude/claude_desktop_config.json` |
| `vscode` | `~/.vscode/mcp.json`, `~/AppData/Roaming/Code/User/settings.json`, `~/AppData/Roaming/Code/User/mcp.json` |

### Expansion logic

1. If **any** target in the input list fails the regex `^[A-Za-z0-9_-]+$`, the entire list is treated as raw file paths (no expansion).
2. Otherwise, each shorthand is looked up in the platform-specific table and expanded to its config path list.
3. Unknown shorthands produce an error.

Example: `--target cursor` on macOS expands to `~/.cursor/mcp.json`.

## Built-in tool definitions

Three clients ship built-in tools that are not configured via MCP but are available to agents. When `--include-builtin` is passed, these are added to the scan results as a synthetic server entry with `protocolVersion: "built-in"`.

### Windsurf

| Tool | Description |
|------|-------------|
| `codebase_search` | Find relevant code snippets across your codebase based on semantic search |
| `find` | Search for files and directories using glob patterns |
| `grep_search` | Search for a specified pattern within files |
| `list_directory` | List the contents of a directory and gather information about file size and number of children directories |
| `read_file` | Read the contents of a file |
| `edit_file` | Make changes to an existing file |
| `write_to_file` | Create new files |
| `run_terminal_command` | Execute terminal commands with internet access and monitor output |

### Cursor

| Tool | Description |
|------|-------------|
| `Read File` | Reads up to 250 lines (750 in max mode) of a file |
| `List Directory` | Read the structure of a directory without reading file contents |
| `Codebase` | Perform semantic searches within your indexed codebase |
| `Grep` | Search for exact keywords or patterns within files |
| `Search Files` | Find files by name using fuzzy matching |
| `Web` | Generate search queries and perform web searches |
| `Fetch Rules` | Retrieve specific rules based on type and description |
| `Edit & Reapply` | Suggest edits to files and apply them automatically |
| `Delete File` | Delete files autonomously (can be disabled in settings) |
| `Terminal` | Execute terminal commands with internet access and monitor output |

### VS Code (Copilot)

| Tool | Description |
|------|-------------|
| `extensions` | Search for extensions in the VS Code Extensions Marketplace |
| `fetch` | Fetch the main content from a web page |
| `findTestFiles` | For a source code file, find the file that contains the tests |
| `githubRepo` | Search a GitHub repository for relevant source code snippets |
| `new` | Scaffold a new workspace in VS Code |
| `openSimpleBrowser` | Preview a locally hosted website in the Simple Browser |
| `problems` | Check errors for a particular file |
| `runCommands` | Run commands in terminal with internet access |
| `runNotebooks` | Run notebook cells |
| `runTasks` | Run tasks and get their output for your workspace |
| `search` | Search and read files in your workspace |
| `searchResults` | The results from the search view |
| `terminalLastCommand` | The active terminal's last run command |
| `terminalSelection` | The active terminal's selection |
| `testFailure` | Information about the last unit test failure |
| `usages` | Find references, definitions, and other usages of a symbol |
| `vscodeAPI` | Use VS Code API references to answer questions about VS Code extensions |
| `changes` | Get diffs of changed files |
| `codebase` | Find relevant file chunks, symbols, and other information in your codebase |
| `editFiles` | Edit files in your workspace |

## Reverse lookup

Given a config file path, the scanner can determine which client it belongs to by expanding `~`, resolving symlinks, and matching against the shorthand resolution table. This is used to:

- Label scan results with the client name
- Look up built-in tool definitions for the matched client
- Generate the synthetic built-in server entry when `--include-builtin` is active
