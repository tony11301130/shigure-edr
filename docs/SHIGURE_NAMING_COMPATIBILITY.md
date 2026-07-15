# Shigure Naming Compatibility

Shigure is the canonical product name. Shiori is legacy prototype naming.

This ticket only changes product-facing labels and documentation where the current product is described. It intentionally does not rename packages, modules, CLI commands, Go module paths, the repository, Windows service defaults, binary names, config filenames, install directories, or data directories.

## Compatibility Names Kept

- Python package/import path: `open_edr_mdr_agent`
- CLI command: `open-edr-mdr-agent`
- Go command path: `agent/cmd/open-edr-agent`
- Windows binary compatibility filename: `shiori-agent.exe`
- Windows package/config compatibility filenames: `shiori-agent-package.zip`, `shiori-agent-config.json`
- Windows service compatibility default: `ShioriAgent`
- Windows install/data compatibility paths: `C:\Program Files\Shiori`, `C:\ProgramData\Shiori`
- Legacy environment variable override: `SHIORI_WINDOWS_AGENT_EXE`

## Remaining `Shiori` Reference Categories

- **Runtime defaults for #17:** `agent/cmd/open-edr-agent/*` and deployment package defaults still use the current Shiori service, binary, and path names until the Windows service lifecycle ticket migrates them coherently.
- **Compatibility tests:** deployment and Go config tests assert the compatibility names above so existing prototype deployments keep working until #17.
- **Compatibility documentation:** README, deployment, and response docs mention Shiori only to label these retained compatibility names and point to the planned runtime migration.
- **Historical research/planning:** research and scratch/spec planning files may mention Shiori when describing the rename decision history.

No broad search-and-replace should be used for the runtime migration. Service names, file names, install paths, data paths, packaging, installer scripts, and compatibility overrides need to move together under the Windows release path work.
