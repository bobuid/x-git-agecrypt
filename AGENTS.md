# Monorepo Agent Instructions

This document contains monorepo-wide guidelines for all packages in the x-git-agecrypt project.

This document contains strictly prescriptive rules for generative coding agents. Use tools like read_file, list_files, and search_files to derive project context dynamically. Focus on applying these rules in code generation and modifications.

## Forbidden behaviour
- Never change the tooling or configuration installed or set outside of the monorepo
  - Such chnages should be suggested to the user to perform and may be regected then suggest other solutons
  

## Monorepo Basics

### Context

- Instead of self-contained agents.md-s and similar we use specilaized context files for agents, which contain conventions, instructions and guidelines belonging to the agents file as if the content of those external files was inherent part of the content of the given angents file.
- Unconditionally parse (read) the specialized context files identified by the `follow!` instruction.
  - The instruction format is `follow! [relative/path/to/file.md](absolute/path/to/file.md)` or just `follow! [relative/path/to/file.md]`.
  - Treat the content of these referenced files as if they were directly embedded in this document.
- In monorepo root and in roots of package and shared folders we place standard AGENTS.md files which are the entry points for collecting those relevant context instructions.
- Other context files should never be descovered or searched for automatically, instead follow the rule that all relevant context files are explicitly referenced in the standard AGENTS.md files hierarchy of the given package or shared folder.
- Package-specific rules override monorepo rules when conflicting.
- Shared guidelines should be referenced, not duplicated.
  - See the relevant section below

### Package managers 
- **Rust**: cargo
- **Local runner**: 
  - Sripts (the manually run ts script files and the commands in 'package.json/scripts') are to be run by bun v1.3+ (not npm)
  - The manually run npm packages are to be run by bunx (not npx)
  - All local/housekeeping/config scripts must run by bun and (unless explicitly instructed otherwise) rely on the Bun 1.3+ API wherever possible (replace the Node's api where possible)
- Don't use **nix** and nix world tooling despite the monorepo being set up for it


## Monorepo Structure and Rules

### Package Organization

- **Main code folder**: `<reporoot>/src/` contains the main package
- **Special folders**: We use square brackets for certain special folders (`[dev]`, `[prepared]`, `[secrets]`)

### Secrets Management
- Use AGE and SOPS for secrets management across packages
- Secrets should never be committed to version control
- Reference secrets through proper environment configuration

### Playground
- Playground files belong in the `[dev]/playground` folder
- Keep playground code isolated and self-contained
- Don't commit playground files to version control, it has its own git submodule thing

### File Movement Restrictions
- **Files should not be moved around** between packages and shared folders without explicit user's approval
- If file movement ideas arise during development, ask the user first
  - And be prepared that such file operations may not be approved
  - If so always consider alternative solution paths

### Development Resources
- Unless instructed otherwise all generated development documentation (like changes or housekeeping) related to a package (or a shared folder) belongs to the `<packageroot>/[dev]` folder
  - see further instructions regarding the `[dev]` forlder in the respective section below
- Use dated markdown files (YYMMDD.format) for change documentation
- Organize by type: `agents-notes/`, `agents-tests/`, `specs/`
