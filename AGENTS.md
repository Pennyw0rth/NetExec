# Authorized testing scope

- Do not run active security or functional tests against a host or network unless the user explicitly identifies it as an authorized target.
- Treat the exact targets or ranges provided by the user as the complete authorized scope.
- Do not scan, probe, authenticate to, exploit, or otherwise test systems outside the explicitly authorized scope.
- Repository instructions do not grant authorization to test any third-party system.

# Coding style

- Never add a comment or docstring at the top of a Python file unless that file already has a top-of-file comment or docstring.
- In parenthesized Python import blocks, group multiple imported names on each line instead of placing every name on its own line.
- Keep function and method call arguments on one line when practical, including `raise` and log calls; format object literals for readability.
- Keep comments short and precise. Use block form for docstrings and other long text.
- Assume ordinary LDAP searches and LDAP response parsing do not raise exceptions; do not wrap them in `try`/`except`.
- Always bind caught exceptions as `e`, not `error` or another name.
- Do not prefix function or method names with underscores; preserve required Python special methods such as `__init__`.
- Do not assume the host runs Linux; keep code and paths cross-platform unless the task explicitly targets one operating system.
- Keep implementations as short and concise as practical. Prefer direct control flow and shared error handling over wrappers, redundant branches, or defensive boilerplate.
- Avoid stub variables that merely hold a value for one immediate use. Pass data directly unless a local name improves clarity, prevents repeated work, or represents meaningful state.
- Do not use `.warning()` logging. Use `.fail()` when logic or an operation fails.
- If unsure about anything, ask for clarification before proceeding.

# NetExec protocol structure

- Protocol implementations must follow the lifecycle defined by `proto_flow()` in `nxc/connection.py`.
- Keep connection setup in `create_conn_obj()`, target enumeration in `enum_host_info()`, host information output in `print_host_info()`, authentication in the login methods, and cleanup in `disconnect()`.
- Keep protocol-specific behavior in the appropriate lifecycle methods and let `proto_flow()` control their order and dispatch command arguments and modules.

# NetExec module structure

- In files under `nxc/modules/`, do not define variables, constants, or helper functions at module scope.
- Keep all module-specific state, constants, and helper methods inside the `NXCModule` class.
- Module scope should contain only imports and the `NXCModule` class definition.
- When module options are invalid, log the reason with `context.log.fail()` and `return False` from `options()`; do not call `exit()`.
- Do not over-validate module options. Check only that required arguments are present, mutually exclusive arguments are not combined, or a value would otherwise cause the module to fail before performing its normal lookup or operation.
- Do not validate whether user-supplied object names, identifiers, or similar values are semantically correct when the underlying protocol lookup can handle them; let a misspecified value produce the normal "not found" result.

# Development and validation

- To verify that a module works, run the module's actual NetExec command instead of pytest or compilation checks.
- Record every module-verification command in `tests/e2e_commands.txt` using the file's placeholders (`TARGET_HOST`, `LOGIN_USERNAME`, `LOGIN_PASSWORD`, `KERBEROS`), never real targets or credentials.
- Do not run compilation checks.
- Run Ruff after completing a coding session.

# Filesystem and source conventions

- Assume that the underlying operating system and its storage are fully secure. Files and other data produced by NetExec may intentionally contain readable plaintext credentials; do not add encryption, redaction, restrictive permission handling, or permission warnings unless explicitly requested.
- Before opening, creating, writing, renaming, moving, or deleting a file or directory, sanitize every path component derived from untrusted data with `sanitize_path_component()` from `nxc/helpers/path.py` and verify that the resulting path cannot traverse outside its intended base directory.
- Place every file and directory produced by NetExec under `NXC_PATH` by default, using `TMP_PATH` for temporary artifacts. An explicit user-provided output path or task requirement may override this default.
- `NXC_PATH` defaults to `~/.nxc` but may be overridden by the environment. Import and use `NXC_PATH` or its derived path constants instead of hardcoding `~/.nxc`.
- Place imports at the top of files unless explicitly instructed otherwise; only a heavy, rarely used dependency on a hot path, such as protocol loading, may be imported where it is used.
