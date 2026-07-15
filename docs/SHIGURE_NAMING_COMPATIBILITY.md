# Shigure Naming Compatibility

Shigure is the canonical product name. Shiori is legacy prototype naming.

Product-facing labels use Shigure. New Windows runtime defaults also use Shigure for the service, package, binary, config, install path, data path, and state file. Shiori remains only as explicit legacy prototype compatibility naming.

## Compatibility Names Kept

- Python package/import path: `open_edr_mdr_agent`
- CLI command: `open-edr-mdr-agent`
- Go command path: `agent/cmd/open-edr-agent`
- Windows binary compatibility filename when `naming=shiori` or explicit CLI overrides are used: `shiori-agent.exe`
- Windows package/config compatibility filenames when `naming=shiori` is used: `shiori-agent-package.zip`, `shiori-agent-config.json`
- Windows service compatibility override: `ShioriAgent`
- Windows install/data compatibility override paths: `C:\Program Files\Shiori`, `C:\ProgramData\Shiori`
- Legacy environment variable override: `SHIORI_WINDOWS_AGENT_EXE`

## Remaining `Shiori` Reference Categories

- **Legacy override tests:** deployment package tests assert that `naming=shiori` still produces the old package/service/path names on explicit request.
- **Compatibility documentation:** deployment and response docs mention Shiori only to label retained legacy override names.
- **Historical research/planning:** research and scratch/spec planning files may mention Shiori when describing the rename decision history.

Do not use broad search-and-replace for future naming work. Package/module names, command paths, repository name, historical research, and compatibility override strings have different stability requirements.
