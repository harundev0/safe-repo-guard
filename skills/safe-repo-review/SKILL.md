<skill_content name="safe-repo-review">
# Skill: safe-repo-review

# Safe Repo Review / Untrusted Codebase Audit

**A universal methodology for safely inspecting and reviewing repositories (especially zip bundles, Google Drive links, or remote freelance git clones) without triggering trojans, malware, or git hook exploits.**

## When to use

Use this skill whenever:
- Evaluating an unknown, unfamiliar, or third-party codebase.
- The user provides a repository archive (e.g. .zip or .tar.gz) or clones a repository directly (`git clone`) from a freelance client, a third-party open-source project without reputational checks, or an unknown Google Drive/Dropbox link.
- The user explicitly asks for a "safety check", "security review", or "check for malware/trojans" in an unfamiliar repository.
- As a prerequisite before performing any actual read/write/run tasks in an untrusted directory workspace.

## Threat Vectors (Why this matters)

Malware in developer repositories typically targets developers' machines through automated execution paths before you even run their app scripts:
1.  **Git Hooks (`.git/hooks/`)**: Attackers place scripts in `post-checkout`, `pre-commit`, `pre-push`, or identical hooks. Any standard git operation executes the malware.
2.  **Git Config Parameters (`.git/config`)**: Attackers override config properties such as `core.hooksPath`, `core.fsmonitor`, or `core.pager`. For example, simply running `git status` executes `fsmonitor` payloads silently.
3.  **Prompt Injection in READMEs**: Hidden prompts trick the LLM Agent into executing compromised setup scripts or data-exfiltration commands. 
4.  **Malicious Build Scripts**: Obfuscated execution commands disguised within `package.json` (`preinstall`, `postinstall`), `Makefile`, or `.sh` setup files. Very common in repos retrieved via `git clone`.
5.  **Malicious Tests**: Embedded downloaders or malware triggers in unit tests, where running `npm test` or `pytest` compromises the host.

## The Triaging Process (Execution Flow)

WARNING: Before doing anything else in an untrusted repo, DO NOT run `git status`, `git checkout`, or any setup scripts. ONLY use read operations (`ls`, `cat`, `grep`).

### Step 1: Read-Only Check
- Prevent the agent flow from auto-approving any script/command execution. If you need to evaluate, only execute safe reading primitives.
- Do not export or process environment files `.env` or SSH keys without checking them. 

### Step 2: Ensure the Workspace is Clean
Use `ls -la` to list all hidden directories. If there is a `.git` folder, proceed with rigorous checks. 

### Step 3: Audit Git Hooks
Search for active git hooks (files *without* the `.sample` extension). 
```bash
ls -la .git/hooks/ | grep -v '\.sample$'
```
IF any active hooks exist, inspect them raw:
```bash
cat .git/hooks/<hook-name>
```

### Step 4: Audit Git Config
Examine the local git configuration to ensure no hijacked commands exist. 
```bash
cat .git/config
```
Look for:
- `hooksPath`
- `fsmonitor`
- `pager`

### Step 5: Grep for Remote Execution Vectors
Search for download-and-execute commands in the `.git` directory and other suspicious places (like package.json scripts or Makefile). 
```bash
grep -E -r '(curl|wget|base64|nc|bash -i|/dev/tcp)' .git/
```

### Step 6: Audit Lifecycle Scripts
Inspect `package.json` or build files for scripts running during install:
```bash
grep -E -i '"(preinstall|install|postinstall|prepare)"' package.json
```

### Step 7: Halt on Suspicion
If ANY of the above checks reveal non-standard, obfuscated, or suspicious scripts (like curl-ing scripts from random IP addresses and executing them), IMMEDIATELY stop the task.
- Warn the user explicitly that a Trojan Downloader or Phishing Execution vector was found.
- Do not run tests, do not install dependencies, and absolutely do not click links.

## Canonical Responses
- "I have completed the Safe Repo Review using strictly read-only diagnostics. I audited `.git/hooks`, `.git/config`, and checked for payload injections. No suspicious payloads were found."
- "WARNING: I found a malicious git hook (`post-checkout`) that downloads a script from an untrusted IP address. This is a common Trojan downloader pattern. I have halted execution and blocked any setup scripts to protect your machine."

</skill_content>