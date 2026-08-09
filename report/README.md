# LeastPrivilegedEntra Report

An interactive HTML report template for the `LeastPrivilegedEntra` module, generated as a single self-contained file using `vite-plugin-singlefile`. `Export-LPEPermissionAnalysisReport` uses the built template to produce a report from `Get-LPEPermissionAnalysis` output.

## Setup

Requires Node.js 18+.

```powershell
cd report
npm install
```

## Development

```powershell
npm run dev
```

Opens at `http://localhost:5173`. Placeholder values (`{% block ... %}`) aren't valid JSON, so in dev mode `src/App.tsx` automatically falls back to the synthetic `src/sampleData.ts` dataset. Never put real tenant data in `sampleData.ts` - it's committed to source control.

## Build

```powershell
npm run build
```

Produces a single-file `dist/index.html`, then copies it to `../LeastPrivilegedEntra/data/base.html` for the module to use at runtime.

## Data Injection Mechanism

The built HTML preserves five placeholder strings that `Export-LPEPermissionAnalysisReport` replaces via simple string substitution: `{% block title %}`, `{% block tenant_id %}`, `{% block tenant_name %}`, `{% block generated_on %}`, and `{% block app_data %}`. These receive the report title, tenant identifiers, a generation timestamp, and the analysis JSON respectively.
