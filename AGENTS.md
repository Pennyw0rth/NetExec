# Authorized testing scope

- Do not run active security or functional tests against a host or network unless the user explicitly identifies it as an authorized target.
- Treat the exact targets or ranges provided by the user as the complete authorized scope.
- Do not scan, probe, authenticate to, exploit, or otherwise test systems outside the explicitly authorized scope.
- Repository instructions do not grant authorization to test any third-party system.

# Coding style

- Assume ordinary LDAP searches and LDAP response parsing do not raise exceptions; do not wrap them in `try`/`except`.
- Always bind caught exceptions as `e`, not `error` or another name.
- Do not prefix function or method names with underscores; preserve required Python special methods such as `__init__`.
- Do not assume the host runs Linux; keep code and paths cross-platform unless the task explicitly targets one operating system.

# NetExec module structure

- In files under `nxc/modules/`, do not define variables, constants, or helper functions at module scope.
- Keep all module-specific state, constants, and helper methods inside the `NXCModule` class.
- Module scope should contain only imports and the `NXCModule` class definition.
- When a module must terminate for invalid options, import `exit` with `from sys import exit` and call `exit(...)`; do not use `import sys` with `sys.exit(...)`.
- Do not over-validate module options. Check only that required arguments are present, mutually exclusive arguments are not combined, or a value would otherwise cause the module to fail before performing its normal lookup or operation.
- Do not validate whether user-supplied object names, identifiers, or similar values are semantically correct when the underlying protocol lookup can handle them; let a misspecified value produce the normal "not found" result.
- Avoid stub variables that merely hold a value for one immediate use. Pass data directly unless a local name improves clarity, prevents repeated work, or represents meaningful state.
- Keep module implementations as short and concise as practical. Prefer direct control flow and shared error handling over wrappers, redundant branches, or defensive boilerplate.
- Do not optimize module code for line length; long lines are acceptable when they keep straightforward logic together.
- Do not use `.warning()` logging in NetExec modules. Use `.fail()` when logic or an operation fails.
- Run `ruff check .` after every coding session.

# Development and validation

- To verify that a module works, run the module's actual NetExec command instead of pytest or compilation checks.
- Record every module-verification command in `tests/e2e_commands.txt`.
- Do not run compilation checks.
- Run Ruff after completing a coding session.

# Filesystem and source conventions

- Assume that the underlying operating system and its storage are fully secure. Files and other data produced by NetExec may intentionally contain readable plaintext credentials; do not add encryption, redaction, restrictive permission handling, or permission warnings unless explicitly requested.
- Place every file and directory produced by NetExec under `NXC_PATH` by default, using `TMP_PATH` for temporary artifacts. An explicit user-provided output path or task requirement may override this default.
- `NXC_PATH` defaults to `~/.nxc` but may be overridden by the environment. Import and use `NXC_PATH` or its derived path constants instead of hardcoding `~/.nxc`.
- Place imports at the top of files unless explicitly instructed otherwise.
