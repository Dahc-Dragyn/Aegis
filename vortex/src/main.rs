use anyhow::{Context, Result};
use clap::Parser;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use serde::Deserialize;
use quote::ToTokens;
use syn::{Item, Visibility, File};
use tiktoken_rs::o200k_base; // Best proxy for modern LLMs (Gemini/o1)

#[derive(Parser, Debug)]
#[command(author, version, about = "Vortex: High-Fidelity LLM Context Generator")]
struct Args {
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    #[arg(short, long, default_value = "vortex_context.md")]
    output: PathBuf,

    #[arg(short, long, default_value = "gemini-2.5-flash-lite")]
    model: String,
}

#[derive(Deserialize, Debug)]
struct Cargo {
    package: Package,
    #[serde(default)]
    dependencies: std::collections::HashMap<String, toml::Value>,
}

#[derive(Deserialize, Debug)]
struct Package {
    name: String,
    version: String,
}

struct ProjectMapper {
    root: PathBuf,
}

impl ProjectMapper {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn build_tree(&self) -> Result<String> {
        let mut tree = String::from("```\n.\n");
        let walker = WalkBuilder::new(&self.root)
            .hidden(true) // Ignore .git, etc.
            .git_ignore(true)
            .require_git(false)
            .build();

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path == self.root { continue; }

            // Skip common noise directories
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "venv" || name == ".venv" || name == "node_modules" || name == "target" {
                continue;
            }

            let depth = entry.depth();

            let indent = "│   ".repeat(depth.saturating_sub(1));
            let branch = if entry.file_type().map(|f| f.is_dir()).unwrap_or(false) {
                format!("{}{}── {}/\n", indent, if depth > 0 { "├" } else { "" }, name)
            } else {
                format!("{}{}── {}\n", indent, if depth > 0 { "├" } else { "" }, name)
            };
            tree.push_str(&branch);
        }
        tree.push_str("```\n");
        Ok(tree)
    }
}

struct ApiSkeleton {
    _path: PathBuf,
    content: String,
}

struct ApiExtractor;

impl ApiExtractor {
    /// Recursively extract public API surface starting from a root file
    fn extract_recursive(
        path: PathBuf,
        visited: Arc<Mutex<HashSet<PathBuf>>>,
    ) -> Result<Vec<ApiSkeleton>> {
        let abs_path = fs::canonicalize(&path).unwrap_or(path.clone());
        
        {
            let mut visited_lock = visited.lock().unwrap();
            if !visited_lock.insert(abs_path.clone()) {
                return Ok(vec![]); // Already visited (Circular protection)
            }
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read source file: {:?}", path))?;
        let syntax_tree: File = syn::parse_file(&content)?;
        
        let mut local_skeleton = format!("#### Module: {:?}\n", path);
        
        // Extract top-level module docstrings (//!)
        for attr in &syntax_tree.attrs {
            if attr.path().is_ident("doc") {
                if let Ok(nv) = attr.meta.require_name_value() {
                    let doc = nv.value.to_token_stream().to_string();
                    local_skeleton.push_str(&format!("> {}\n", doc.trim_matches('"')));
                }
            }
        }

        local_skeleton.push_str("```rust\n");
        let mut sub_module_paths = Vec::new();

        for item in syntax_tree.items {
            if let Some(sig) = Self::get_public_signature(&item) {
                local_skeleton.push_str(&format!("{};\n", sig));
            }

            // Detect sub-modules (pub mod foo;)
            if let Item::Mod(m) = item {
                if matches!(m.vis, Visibility::Public(_)) {
                    if m.content.is_some() {
                        // Inline mod: Content already processed if we used a visitor, 
                        // but here we just list the signature.
                    } else {
                        // External mod: Resolve path
                        if let Some(mod_path) = Self::resolve_mod_path(&path, &m.ident.to_string()) {
                            sub_module_paths.push(mod_path);
                        }
                    }
                }
            }
        }
        local_skeleton.push_str("```\n");

        let mut all_skeletons = vec![ApiSkeleton {
            _path: path.clone(),
            content: local_skeleton,
        }];

        // Parallel recursion for sub-modules
        if !sub_module_paths.is_empty() {
            let sub_results: Vec<Result<Vec<ApiSkeleton>>> = sub_module_paths
                .into_par_iter()
                .map(|p| Self::extract_recursive(p, Arc::clone(&visited)))
                .collect();

            for res in sub_results {
                all_skeletons.extend(res?);
            }
        }

        Ok(all_skeletons)
    }

    fn resolve_mod_path(parent_path: &Path, mod_name: &str) -> Option<PathBuf> {
        let parent_dir = parent_path.parent()?;
        let stem = parent_path.file_stem()?.to_str()?;
        
        // Case 1: src/main.rs -> src/foo.rs or src/foo/mod.rs
        // Case 2: src/foo.rs -> src/foo/bar.rs or src/foo/bar/mod.rs
        
        let mut candidates = Vec::new();
        if stem == "main" || stem == "lib" || parent_path.ends_with("mod.rs") {
            candidates.push(parent_dir.join(format!("{}.rs", mod_name)));
            candidates.push(parent_dir.join(mod_name).join("mod.rs"));
        } else {
            let sub_dir = parent_dir.join(stem);
            candidates.push(sub_dir.join(format!("{}.rs", mod_name)));
            candidates.push(sub_dir.join(mod_name).join("mod.rs"));
        }

        candidates.into_iter().find(|p| p.exists())
    }

    fn get_public_signature(item: &Item) -> Option<String> {
        match item {
            Item::Fn(f) if matches!(f.vis, Visibility::Public(_)) => {
                Some(f.sig.to_token_stream().to_string())
            }
            Item::Struct(s) if matches!(s.vis, Visibility::Public(_)) => {
                let mut sig = format!("struct {}", s.ident);
                if !s.generics.params.is_empty() {
                    sig.push_str(&s.generics.to_token_stream().to_string());
                }
                Some(sig)
            }
            Item::Enum(e) if matches!(e.vis, Visibility::Public(_)) => {
                let mut sig = format!("enum {}", e.ident);
                if !e.generics.params.is_empty() {
                    sig.push_str(&e.generics.to_token_stream().to_string());
                }
                Some(sig)
            }
            Item::Trait(t) if matches!(t.vis, Visibility::Public(_)) => {
                Some(format!("trait {}", t.ident))
            }
            Item::Macro(m) => {
                // Check for #[macro_export]
                let is_exported = m.attrs.iter().any(|attr| attr.path().is_ident("macro_export"));
                if is_exported {
                    if let Some(ident) = &m.ident {
                        return Some(format!("macro_rules! {}", ident));
                    }
                }
                None
            }
            Item::Mod(m) if matches!(m.vis, Visibility::Public(_)) => {
                Some(format!("pub mod {}", m.ident))
            }
            _ => None,
        }
    }
}

struct DependencyLedger {
    path: PathBuf,
}

impl DependencyLedger {
    fn new(root: &Path) -> Self {
        Self { path: root.join("Cargo.toml") }
    }

    fn parse(&self) -> Result<String> {
        if !self.path.exists() {
            return Ok("No Cargo.toml found.".to_string());
        }

        let content = fs::read_to_string(&self.path)?;
        let cargo: Cargo = toml::from_str(&content)?;

        let mut ledger = format!("### Project: {} v{}\n\n| Dependency | Version |\n| --- | --- |\n", 
            cargo.package.name, cargo.package.version);

        let mut entries: Vec<_> = cargo.dependencies.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, value) in entries {
            let version = match value {
                toml::Value::String(v) => v,
                toml::Value::Table(map) => {
                    map.get("version")
                        .and_then(|v: &toml::Value| v.as_str())
                        .unwrap_or("inline/path")
                        .to_string()
                },
                _ => "unknown".to_string(),
            };
            ledger.push_str(&format!("| {} | {} |\n", name, version));
        }

        Ok(ledger)
    }
}

fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();
    
    let args = Args::parse();
    println!("Vortex 🌀 Generating context for model: {}", args.model);

    // Phase 1: Mapping
    let mapper = ProjectMapper::new(args.path.clone());
    let tree = mapper.build_tree()?;
    println!("- Project map generated.");

    // Phase 2: Recursive Public API Extraction
    let mut roots = Vec::new();
    let src_dir = args.path.join("src");
    if src_dir.join("lib.rs").exists() {
        roots.push(src_dir.join("lib.rs"));
    }
    if src_dir.join("main.rs").exists() {
        roots.push(src_dir.join("main.rs"));
    }
    
    // Also include bin/ files if they exist
    let bin_dir = src_dir.join("bin");
    if bin_dir.exists() {
        if let Ok(entries) = fs::read_dir(bin_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().extension().map(|e| e == "rs").unwrap_or(false) {
                    roots.push(entry.path());
                }
            }
        }
    }

    if roots.is_empty() {
        println!("- WARNING: No entry points (lib.rs/main.rs) found. API extraction might be empty.");
    } else {
        println!("- Found {} entry points. Climbing module graph...", roots.len());
    }
    
    let visited = Arc::new(Mutex::new(HashSet::new()));
    let mut api_skeletons = Vec::new();

    for root in roots {
        let results = ApiExtractor::extract_recursive(root, Arc::clone(&visited))?;
        for skel in results {
            api_skeletons.push(skel.content);
        }
    }

    // Phase 3: Dependencies
    let ledger = DependencyLedger::new(&args.path);
    let deps = ledger.parse()?;
    println!("- Dependency ledger parsed.");

    // Phase 4: Token Counting
    let mut final_context = String::from("# Vortex🌀 LLM Context Snapshot\n\n");
    final_context.push_str("## Project Tree Map\n");
    final_context.push_str(&tree);
    final_context.push_str("\n## Dependency Ledger\n");
    final_context.push_str(&deps);
    final_context.push_str("\n## Public API Skeleton\n");
    for skel in api_skeletons {
        final_context.push_str(&skel);
        final_context.push('\n');
    }

    // Heuristic Token Counting (o200k_base proxy for Gemini)
    let bpe = o200k_base().unwrap();
    let token_count = bpe.encode_with_special_tokens(&final_context).len();
    
    final_context.push_str(&format!("\n\n---\n**Total Tokens (Gemini Proxy/o200k):** {}\n", token_count));

    fs::write(&args.output, final_context)
        .with_context(|| format!("Failed to write output to {:?}", args.output))?;

    println!("Success! Vortex delivered context at {:?}. Total Tokens: {}", args.output, token_count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_dependency_ledger_missing_file() {
        let dir = tempdir().unwrap();
        let ledger = DependencyLedger::new(dir.path());
        let result = ledger.parse().unwrap();
        assert_eq!(result, "No Cargo.toml found.");
    }

    #[test]
    fn test_project_mapper_gitignore_respect() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create a fake project structure
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("src/main.rs"), "fn main() {}")?;
        fs::write(root.join("secret.txt"), "private data")?;
        
        // Add a .gitignore to ignore the secret file
        fs::write(root.join(".gitignore"), "secret.txt\n")?;

        let mapper = ProjectMapper::new(root.to_path_buf());
        let tree = mapper.build_tree()?;

        // Verify secret.txt is NOT in the tree
        assert!(!tree.contains("secret.txt"), "Tree should not contain gitignored files");
        assert!(tree.contains("main.rs"), "Tree should contain valid source files");

        Ok(())
    }

    #[test]
    fn test_api_extractor_public_items() -> Result<()> {
        let code = r#"
            //! Module level doc
            pub struct PublicStruct { pub field: i32 }
            struct PrivateStruct;
            pub fn public_fn(a: i32) -> bool { true }
            fn private_fn() {}
            pub enum PublicEnum { Variant }
        "#;
        
        let syntax_tree: File = syn::parse_file(code)?;
        let mut extracted = Vec::new();

        for item in syntax_tree.items {
            if let Some(sig) = ApiExtractor::get_public_signature(&item) {
                extracted.push(sig);
            }
        }

        assert_eq!(extracted.len(), 3);
        assert!(extracted.iter().any(|s| s.contains("struct PublicStruct")));
        assert!(extracted.iter().any(|s| s.contains("fn public_fn")));
        assert!(extracted.iter().any(|s| s.contains("enum PublicEnum")));
        assert!(!extracted.iter().any(|s| s.contains("PrivateStruct")));

        Ok(())
    }

    #[test]
    fn test_recursive_api_extraction() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();
        let src = root.join("src");
        fs::create_dir(&src)?;

        // lib.rs -> pub mod a; mod b;
        fs::write(src.join("lib.rs"), "pub mod a; mod b;")?;
        
        // a.rs -> pub struct A;
        fs::write(src.join("a.rs"), "pub struct A;")?;

        // b.rs -> pub struct B; (should be ignored because b is private)
        fs::write(src.join("b.rs"), "pub struct B;")?;

        let visited = Arc::new(Mutex::new(HashSet::new()));
        let results = ApiExtractor::extract_recursive(src.join("lib.rs"), visited)?;

        // Should find lib.rs and a.rs, ignore b.rs
        assert_eq!(results.len(), 2, "Should find lib.rs and a.rs");
        
        let all_content = results.iter().map(|s| s.content.as_str()).collect::<Vec<_>>().join("\n");
        assert!(all_content.contains("struct A"));
        assert!(!all_content.contains("struct B"));

        Ok(())
    }

    #[test]
    fn test_macro_export_extraction() -> Result<()> {
        let code = r#"
            #[macro_export]
            macro_rules! my_macro { () => {} }
            
            macro_rules! private_macro { () => {} }
        "#;
        
        let syntax_tree: File = syn::parse_file(code)?;
        let mut extracted = Vec::new();

        for item in syntax_tree.items {
            if let Some(sig) = ApiExtractor::get_public_signature(&item) {
                extracted.push(sig);
            }
        }

        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].contains("macro_rules! my_macro"));
        assert!(!extracted[0].contains("private_macro"));

        Ok(())
    }
}
