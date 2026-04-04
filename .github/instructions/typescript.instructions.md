---
applyTo: "sdk/ts/**"
---

# TypeScript SDK review guidelines

- ESM-only: relative imports must use `.js` extensions. Flag relative imports missing the `.js` extension (package imports and `node:` built-ins are fine).
- Strict TypeScript: no `any`, no type assertions unless unavoidable. Flag `as` casts and `any` types.
- Use `import type` for type-only imports (`verbatimModuleSyntax` is enabled).
- Zero runtime dependencies — only `node:crypto` and `node:sqlite`. Flag any new dependency additions.
- No default exports. Flag `export default`.
- Colocated tests: `foo.ts` → `foo.test.ts` in the same directory.
- Biome for formatting (tab indentation, double quotes).
