use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{LocalCommandSpec, ensure_secure_absolute_directory, run_local_command};
use crate::error::{BridgeError, BridgeResult};

const MCP_NAME: &str = "ssh-bridge";
const CODEX_PATH_WARNING: &str = "WARNING: proceeding, even though we could not create PATH aliases: Read-only file system (os error 30)";
const CODEX_MISSING: &str = "Error: No MCP server named 'ssh-bridge' found.";
const LOCAL_OUTPUT_LIMIT: usize = 1024 * 1024;
const LOCAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct InstallLayout {
    pub binary: PathBuf,
    pub plugin_manifest: PathBuf,
    pub mcp_manifest: PathBuf,
    pub skill_source: PathBuf,
    pub skill_target: PathBuf,
    pub identity_file: PathBuf,
    pub codex_executable: PathBuf,
}

impl InstallLayout {
    pub fn discover() -> BridgeResult<Self> {
        let binary = std::env::current_exe().map_err(BridgeError::io)?;
        let binary = fs::canonicalize(binary).map_err(BridgeError::io)?;
        let bin_directory = binary
            .parent()
            .ok_or_else(|| BridgeError::invalid_config("release binary has no parent directory"))?;
        if bin_directory.file_name() != Some(OsStr::new("bin")) {
            return Err(BridgeError::invalid_config(
                "install must run from the packaged bin/codex-ssh-bridge binary",
            ));
        }
        let bundle = bin_directory
            .parent()
            .ok_or_else(|| BridgeError::invalid_config("packaged binary has no bundle root"))?
            .to_owned();
        let home = nonempty_environment("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| BridgeError::invalid_config("HOME is required for --user install"))?;
        if !home.is_absolute() {
            return Err(BridgeError::invalid_config("HOME must be an absolute path"));
        }
        let state_base = nonempty_environment("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        Ok(Self {
            binary,
            plugin_manifest: bundle.join(".codex-plugin/plugin.json"),
            mcp_manifest: bundle.join(".mcp.json"),
            skill_source: bundle.join("skills/remote-ssh-ops"),
            skill_target: home.join(".agents/skills/remote-ssh-ops"),
            identity_file: state_base.join("codex-ssh-bridge/install.toml"),
            codex_executable: find_executable("codex")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallReport {
    pub applied: bool,
    pub installation_id: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationIdentity {
    version: u32,
    installation_id: String,
    binary: String,
    binary_sha256: String,
    plugin_manifest: String,
    plugin_sha256: String,
    mcp_manifest: String,
    mcp_sha256: String,
    skill_source: String,
    skill_sha256: String,
    skill_target: String,
    codex_executable: String,
}

#[derive(Debug, Clone)]
struct ResolvedInstall {
    layout: InstallLayout,
    identity: InstallationIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Absent,
    Matching,
}

pub async fn install_user(layout: InstallLayout, apply: bool) -> BridgeResult<InstallReport> {
    let resolved = resolve_layout(layout)?;
    let mcp = codex_get(&resolved).await?;
    let skill = skill_presence(&resolved)?;
    let marker = marker_presence(&resolved)?;
    let actions = vec![
        match mcp {
            Presence::Absent => "register MCP ssh-bridge".to_owned(),
            Presence::Matching => "MCP ssh-bridge already matches".to_owned(),
        },
        match skill {
            Presence::Absent => "create remote-ssh-ops Skill symlink".to_owned(),
            Presence::Matching => "remote-ssh-ops Skill symlink already matches".to_owned(),
        },
        match marker {
            Presence::Absent => "write private installation identity".to_owned(),
            Presence::Matching => "installation identity already matches".to_owned(),
        },
    ];
    if !apply {
        return Ok(report(false, &resolved, actions));
    }

    let mut journal = InstallJournal::default();
    let applied = async {
        if mcp == Presence::Absent {
            if codex_get(&resolved).await? != Presence::Absent {
                return Err(BridgeError::invalid_config(
                    "MCP entry changed after installation preflight",
                ));
            }
            if let Err(error) = codex_add(&resolved).await {
                if matches!(codex_get(&resolved).await, Ok(Presence::Matching)) {
                    journal.mcp_added = true;
                }
                return Err(error);
            }
            journal.mcp_added = true;
        }
        if skill == Presence::Absent {
            if skill_presence(&resolved)? != Presence::Absent {
                return Err(BridgeError::invalid_config(
                    "Skill destination changed after installation preflight",
                ));
            }
            let parent = resolved
                .layout
                .skill_target
                .parent()
                .expect("absolute Skill target has a parent");
            journal
                .created_directories
                .extend(ensure_secure_absolute_directory(parent)?);
            symlink(&resolved.layout.skill_source, &resolved.layout.skill_target)
                .map_err(BridgeError::io)?;
            journal.skill_created = true;
        }
        if marker == Presence::Absent {
            if marker_presence(&resolved)? != Presence::Absent {
                return Err(BridgeError::invalid_config(
                    "installation identity changed after preflight",
                ));
            }
            let parent = resolved
                .layout
                .identity_file
                .parent()
                .expect("absolute identity path has a parent");
            journal
                .created_directories
                .extend(ensure_secure_absolute_directory(parent)?);
            write_identity_noclobber(&resolved)?;
            journal.marker_created = true;
        }
        Ok(())
    }
    .await;
    if let Err(error) = applied {
        if rollback_install(&resolved, &journal).await.is_err() {
            return Err(BridgeError::new(
                crate::ErrorCode::Io,
                "installation failed and rollback was incomplete",
                false,
            ));
        }
        return Err(error);
    }
    Ok(report(true, &resolved, actions))
}

pub async fn uninstall_user(layout: InstallLayout, apply: bool) -> BridgeResult<InstallReport> {
    let resolved = resolve_layout(layout)?;
    if marker_presence(&resolved)? != Presence::Matching {
        return Err(BridgeError::invalid_config(
            "recorded installation identity is missing",
        ));
    }
    let mcp = codex_get(&resolved).await?;
    let skill = skill_presence(&resolved)?;
    let actions = vec![
        match mcp {
            Presence::Absent => "MCP ssh-bridge is already absent".to_owned(),
            Presence::Matching => "remove identity-matching MCP ssh-bridge".to_owned(),
        },
        match skill {
            Presence::Absent => "remote-ssh-ops Skill symlink is already absent".to_owned(),
            Presence::Matching => "remove identity-matching Skill symlink".to_owned(),
        },
        "remove private installation identity".to_owned(),
    ];
    if !apply {
        return Ok(report(false, &resolved, actions));
    }

    let mut mcp_removed = false;
    let mut skill_removed = false;
    let removed = async {
        if mcp == Presence::Matching {
            if codex_get(&resolved).await? != Presence::Matching {
                return Err(BridgeError::invalid_config(
                    "MCP entry changed after uninstall preflight",
                ));
            }
            codex_remove(&resolved).await?;
            mcp_removed = true;
        }
        if skill == Presence::Matching {
            if skill_presence(&resolved)? != Presence::Matching {
                return Err(BridgeError::invalid_config(
                    "Skill destination changed after uninstall preflight",
                ));
            }
            fs::remove_file(&resolved.layout.skill_target).map_err(BridgeError::io)?;
            skill_removed = true;
        }
        if marker_presence(&resolved)? != Presence::Matching {
            return Err(BridgeError::invalid_config(
                "installation identity changed after uninstall preflight",
            ));
        }
        fs::remove_file(&resolved.layout.identity_file).map_err(BridgeError::io)?;
        Ok(())
    }
    .await;
    if let Err(error) = removed {
        let mut rollback_failed = false;
        if skill_removed
            && symlink(&resolved.layout.skill_source, &resolved.layout.skill_target).is_err()
        {
            rollback_failed = true;
        }
        if mcp_removed && codex_add(&resolved).await.is_err() {
            rollback_failed = true;
        }
        if rollback_failed {
            return Err(BridgeError::new(
                crate::ErrorCode::Io,
                "uninstall failed and rollback was incomplete",
                false,
            ));
        }
        return Err(error);
    }
    Ok(report(true, &resolved, actions))
}

#[derive(Default)]
struct InstallJournal {
    mcp_added: bool,
    skill_created: bool,
    marker_created: bool,
    created_directories: Vec<PathBuf>,
}

async fn rollback_install(
    resolved: &ResolvedInstall,
    journal: &InstallJournal,
) -> BridgeResult<()> {
    let mut failed = false;
    if journal.marker_created
        && matches!(marker_presence(resolved), Ok(Presence::Matching))
        && fs::remove_file(&resolved.layout.identity_file).is_err()
    {
        failed = true;
    }
    if journal.skill_created
        && matches!(skill_presence(resolved), Ok(Presence::Matching))
        && fs::remove_file(&resolved.layout.skill_target).is_err()
    {
        failed = true;
    }
    if journal.mcp_added {
        match codex_get(resolved).await {
            Ok(Presence::Matching) => {
                if codex_remove(resolved).await.is_err() {
                    failed = true;
                }
            }
            Ok(Presence::Absent) => {}
            Err(error) if error.code == crate::ErrorCode::InvalidConfig => {
                // A concurrently replaced entry is not ours to remove.
            }
            Err(_) => failed = true,
        }
    }
    for directory in journal.created_directories.iter().rev() {
        if let Err(error) = fs::remove_dir(directory)
            && error.kind() != std::io::ErrorKind::NotFound
            && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
        {
            failed = true;
        }
    }
    if failed {
        Err(BridgeError::io("rollback could not restore every mutation"))
    } else {
        Ok(())
    }
}

fn resolve_layout(layout: InstallLayout) -> BridgeResult<ResolvedInstall> {
    let binary = canonical_secure_file(&layout.binary, true)?;
    let plugin_manifest = canonical_secure_file(&layout.plugin_manifest, false)?;
    let mcp_manifest = canonical_secure_file(&layout.mcp_manifest, false)?;
    let codex_executable = canonical_secure_file(&layout.codex_executable, true)?;
    let skill_source = fs::canonicalize(&layout.skill_source).map_err(BridgeError::io)?;
    let skill_metadata = fs::metadata(&skill_source).map_err(BridgeError::io)?;
    if !skill_metadata.is_dir() {
        return Err(BridgeError::invalid_config(
            "Skill source must be a directory",
        ));
    }
    validate_package_layout(&binary, &plugin_manifest, &mcp_manifest, &skill_source)?;
    let skill_files = [
        skill_source.join("SKILL.md"),
        skill_source.join("agents/openai.yaml"),
        skill_source.join("references/operations.md"),
    ];
    for file in &skill_files {
        canonical_secure_file(file, false)?;
    }
    if !layout.skill_target.is_absolute() || !layout.identity_file.is_absolute() {
        return Err(BridgeError::invalid_config(
            "installation destinations must be absolute paths",
        ));
    }
    let binary_hash = sha256_file(&binary)?;
    let plugin_hash = sha256_file(&plugin_manifest)?;
    let mcp_hash = sha256_file(&mcp_manifest)?;
    let mut skill_hasher = Sha256::new();
    for file in &skill_files {
        skill_hasher.update(sha256_file(file)?.as_bytes());
    }
    let skill_hash = hex_digest(&skill_hasher.finalize());
    let strings = [
        path_string(&binary)?,
        binary_hash.clone(),
        path_string(&plugin_manifest)?,
        plugin_hash.clone(),
        path_string(&mcp_manifest)?,
        mcp_hash.clone(),
        path_string(&skill_source)?,
        skill_hash.clone(),
        path_string(&layout.skill_target)?,
        path_string(&codex_executable)?,
    ];
    let mut id_hasher = Sha256::new();
    id_hasher.update(b"codex-ssh-bridge-installation-v1\0");
    for value in &strings {
        id_hasher.update((value.len() as u64).to_be_bytes());
        id_hasher.update(value.as_bytes());
    }
    let identity = InstallationIdentity {
        version: 1,
        installation_id: hex_digest(&id_hasher.finalize()),
        binary: strings[0].clone(),
        binary_sha256: binary_hash,
        plugin_manifest: strings[2].clone(),
        plugin_sha256: plugin_hash,
        mcp_manifest: strings[4].clone(),
        mcp_sha256: mcp_hash,
        skill_source: strings[6].clone(),
        skill_sha256: skill_hash,
        skill_target: strings[8].clone(),
        codex_executable: strings[9].clone(),
    };
    Ok(ResolvedInstall {
        layout: InstallLayout {
            binary,
            plugin_manifest,
            mcp_manifest,
            skill_source,
            skill_target: layout.skill_target,
            identity_file: layout.identity_file,
            codex_executable,
        },
        identity,
    })
}

fn validate_package_layout(
    binary: &Path,
    plugin_manifest: &Path,
    mcp_manifest: &Path,
    skill_source: &Path,
) -> BridgeResult<()> {
    let plugin_directory = plugin_manifest
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("plugin manifest has no parent"))?;
    if plugin_directory.file_name() != Some(OsStr::new(".codex-plugin")) {
        return Err(BridgeError::invalid_config(
            "plugin manifest is not under .codex-plugin",
        ));
    }
    let bundle = plugin_directory
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("plugin manifest has no bundle root"))?;
    if plugin_manifest != bundle.join(".codex-plugin/plugin.json")
        || binary != bundle.join("bin/codex-ssh-bridge")
        || mcp_manifest != bundle.join(".mcp.json")
        || skill_source != bundle.join("skills/remote-ssh-ops")
    {
        return Err(BridgeError::invalid_config(
            "installation files do not form one canonical packaged bundle",
        ));
    }

    let plugin = read_json_bounded(plugin_manifest, 256 * 1024, "plugin manifest")?;
    if plugin.get("name").and_then(serde_json::Value::as_str) != Some("codex-ssh-bridge")
        || plugin.get("skills").and_then(serde_json::Value::as_str) != Some("./skills/")
        || plugin.get("mcpServers").and_then(serde_json::Value::as_str) != Some("./.mcp.json")
    {
        return Err(BridgeError::invalid_config(
            "plugin manifest does not describe codex-ssh-bridge",
        ));
    }

    let mcp = read_json_bounded(mcp_manifest, 256 * 1024, "MCP manifest")?;
    let server = mcp
        .get("mcpServers")
        .and_then(|servers| servers.get(MCP_NAME))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| BridgeError::invalid_config("MCP manifest has no ssh-bridge server"))?;
    if server.get("command").and_then(serde_json::Value::as_str) != Some("./bin/codex-ssh-bridge")
        || server.get("args") != Some(&serde_json::json!(["mcp"]))
    {
        return Err(BridgeError::invalid_config(
            "MCP manifest does not launch the packaged Rust bridge",
        ));
    }

    let skill_document = read_bounded(&skill_source.join("SKILL.md"), 256 * 1024)?;
    let skill_document = std::str::from_utf8(&skill_document)
        .map_err(|_| BridgeError::invalid_config("Skill manifest is not UTF-8"))?;
    if skill_frontmatter_name(skill_document).as_deref() != Some("remote-ssh-ops") {
        return Err(BridgeError::invalid_config(
            "Skill manifest name is not remote-ssh-ops",
        ));
    }
    let agent = read_bounded(&skill_source.join("agents/openai.yaml"), 256 * 1024)?;
    let agent = std::str::from_utf8(&agent)
        .map_err(|_| BridgeError::invalid_config("Skill agent metadata is not UTF-8"))?;
    let agent_lines: Vec<&str> = agent.lines().map(str::trim).collect();
    if !agent_lines.contains(&"- type: \"mcp\"") || !agent_lines.contains(&"value: \"ssh-bridge\"")
    {
        return Err(BridgeError::invalid_config(
            "Skill agent metadata does not depend on MCP ssh-bridge",
        ));
    }
    Ok(())
}

fn read_json_bounded(path: &Path, maximum: u64, label: &str) -> BridgeResult<serde_json::Value> {
    let bytes = read_bounded(path, maximum)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| BridgeError::invalid_config(format!("{label} is not valid JSON")))
}

fn skill_frontmatter_name(document: &str) -> Option<String> {
    let mut lines = document.lines();
    if lines.next()? != "---" {
        return None;
    }
    let mut name = None;
    for line in lines {
        if line == "---" {
            return name;
        }
        if let Some(value) = line.strip_prefix("name:") {
            if name.is_some() {
                return None;
            }
            name = Some(value.trim().trim_matches(['\'', '"']).to_owned());
        }
    }
    None
}

async fn codex_get(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    let output = run_codex(resolved, ["mcp", "get", MCP_NAME, "--json"]).await?;
    if output.status == 1 && output.stdout.is_empty() && codex_missing(&output.stderr) {
        return Ok(Presence::Absent);
    }
    if output.status != 0 {
        return Err(BridgeError::io(
            "`codex mcp get` failed; it was not classified as not-found",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| BridgeError::io("`codex mcp get --json` returned invalid JSON"))?;
    if !mcp_matches(&value, &resolved.layout.binary)? {
        return Err(BridgeError::invalid_config(
            "an MCP server named ssh-bridge has a different configuration",
        ));
    }
    Ok(Presence::Matching)
}

fn codex_missing(stderr: &[u8]) -> bool {
    let Ok(stderr) = std::str::from_utf8(stderr) else {
        return false;
    };
    let mut warning_seen = false;
    let remaining: Vec<&str> = stderr
        .trim()
        .lines()
        .filter(|line| {
            if !warning_seen && *line == CODEX_PATH_WARNING {
                warning_seen = true;
                false
            } else {
                true
            }
        })
        .collect();
    remaining == [CODEX_MISSING]
}

fn mcp_matches(value: &serde_json::Value, binary: &Path) -> BridgeResult<bool> {
    let Some(transport) = value
        .get("transport")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(false);
    };
    if transport.get("type").and_then(serde_json::Value::as_str) != Some("stdio") {
        return Ok(false);
    }
    let Some(command) = transport.get("command").and_then(serde_json::Value::as_str) else {
        return Ok(false);
    };
    let command = match fs::canonicalize(command) {
        Ok(command) => command,
        Err(_) => return Ok(false),
    };
    if command != binary {
        return Ok(false);
    }
    if transport.get("args") != Some(&serde_json::json!(["mcp"])) {
        return Ok(false);
    }
    if !null_or_empty_object(transport.get("env"))
        || !transport.get("cwd").is_none_or(serde_json::Value::is_null)
    {
        return Ok(false);
    }
    Ok(true)
}

fn null_or_empty_object(value: Option<&serde_json::Value>) -> bool {
    value.is_none_or(|value| {
        value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
    })
}

async fn codex_add(resolved: &ResolvedInstall) -> BridgeResult<()> {
    let binary = path_string(&resolved.layout.binary)?;
    let output = run_codex_os(
        resolved,
        vec![
            OsString::from("mcp"),
            OsString::from("add"),
            OsString::from(MCP_NAME),
            OsString::from("--"),
            OsString::from(binary),
            OsString::from("mcp"),
        ],
    )
    .await?;
    if output.status != 0 {
        return Err(BridgeError::io("`codex mcp add` failed"));
    }
    Ok(())
}

async fn codex_remove(resolved: &ResolvedInstall) -> BridgeResult<()> {
    let output = run_codex(resolved, ["mcp", "remove", MCP_NAME]).await?;
    if output.status != 0 {
        return Err(BridgeError::io("`codex mcp remove` failed"));
    }
    Ok(())
}

async fn run_codex<const N: usize>(
    resolved: &ResolvedInstall,
    arguments: [&str; N],
) -> BridgeResult<super::LocalCommandOutput> {
    run_codex_os(
        resolved,
        arguments.into_iter().map(OsString::from).collect(),
    )
    .await
}

async fn run_codex_os(
    resolved: &ResolvedInstall,
    arguments: Vec<OsString>,
) -> BridgeResult<super::LocalCommandOutput> {
    run_local_command(LocalCommandSpec {
        executable: resolved.layout.codex_executable.clone(),
        arguments,
        timeout: LOCAL_TIMEOUT,
        max_output_bytes: LOCAL_OUTPUT_LIMIT,
    })
    .await
}

fn skill_presence(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    match fs::symlink_metadata(&resolved.layout.skill_target) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                return Err(BridgeError::invalid_config(
                    "Skill destination exists and is not this installation's symlink",
                ));
            }
            let target = fs::canonicalize(&resolved.layout.skill_target).map_err(|_| {
                BridgeError::invalid_config("Skill destination symlink is dangling")
            })?;
            if target != resolved.layout.skill_source {
                return Err(BridgeError::invalid_config(
                    "Skill destination resolves to a different source",
                ));
            }
            Ok(Presence::Matching)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Presence::Absent),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn marker_presence(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    match fs::symlink_metadata(&resolved.layout.identity_file) {
        Ok(metadata) => {
            validate_private_identity_file(&metadata)?;
            let contents = read_bounded(&resolved.layout.identity_file, 64 * 1024)?;
            let identity: InstallationIdentity =
                toml::from_str(std::str::from_utf8(&contents).map_err(|_| {
                    BridgeError::invalid_config("installation identity is not UTF-8")
                })?)
                .map_err(|_| BridgeError::invalid_config("installation identity is invalid"))?;
            if identity != resolved.identity {
                return Err(BridgeError::invalid_config(
                    "recorded installation identity differs from this bundle",
                ));
            }
            Ok(Presence::Matching)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Presence::Absent),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn write_identity_noclobber(resolved: &ResolvedInstall) -> BridgeResult<()> {
    let parent = resolved
        .layout
        .identity_file
        .parent()
        .expect("identity path has parent");
    let serialized = toml::to_string_pretty(&resolved.identity)
        .map_err(|_| BridgeError::io("cannot serialize installation identity"))?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(BridgeError::io)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(BridgeError::io)?;
    temporary
        .write_all(serialized.as_bytes())
        .map_err(BridgeError::io)?;
    temporary.flush().map_err(BridgeError::io)?;
    temporary.as_file().sync_all().map_err(BridgeError::io)?;
    temporary
        .persist_noclobber(&resolved.layout.identity_file)
        .map_err(|error| BridgeError::io(error.error))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(BridgeError::io)?;
    Ok(())
}

fn canonical_secure_file(path: &Path, executable: bool) -> BridgeResult<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(BridgeError::io)?;
    let metadata = fs::metadata(&canonical).map_err(BridgeError::io)?;
    validate_trusted_source_file(&metadata, executable)?;
    Ok(canonical)
}

fn validate_trusted_source_file(metadata: &fs::Metadata, executable: bool) -> BridgeResult<()> {
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    if !metadata.is_file()
        || !trusted_source_owner(metadata.uid(), uid, root_uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(BridgeError::invalid_config(
            "installation sources must be regular, root/current-user-owned, and not group/other writable",
        ));
    }
    if executable && metadata.mode() & 0o111 == 0 {
        return Err(BridgeError::invalid_config(
            "installation executable is not executable",
        ));
    }
    Ok(())
}

fn trusted_source_owner(file_uid: u32, effective_uid: u32, root_uid: u32) -> bool {
    file_uid == 0 || file_uid == effective_uid || file_uid == root_uid
}

fn validate_private_identity_file(metadata: &fs::Metadata) -> BridgeResult<()> {
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(BridgeError::invalid_config(
            "installation identity must be a private current-user-owned regular file",
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> BridgeResult<String> {
    let mut file = fs::File::open(path).map_err(BridgeError::io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(BridgeError::io)?;
        if count == 0 {
            return Ok(hex_digest(&hasher.finalize()));
        }
        hasher.update(&buffer[..count]);
    }
}

fn read_bounded(path: &Path, maximum: u64) -> BridgeResult<Vec<u8>> {
    let file = fs::File::open(path).map_err(BridgeError::io)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(BridgeError::io)?;
    if bytes.len() as u64 > maximum {
        return Err(BridgeError::invalid_config(
            "installation identity exceeds its size limit",
        ));
    }
    Ok(bytes)
}

fn path_string(path: &Path) -> BridgeResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| BridgeError::invalid_config("installation paths must be valid UTF-8"))
}

fn hex_digest(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn report(applied: bool, resolved: &ResolvedInstall, actions: Vec<String>) -> InstallReport {
    InstallReport {
        applied,
        installation_id: resolved.identity.installation_id.clone(),
        actions,
    }
}

fn find_executable(name: &str) -> BridgeResult<PathBuf> {
    let path = nonempty_environment("PATH")
        .ok_or_else(|| BridgeError::invalid_config("PATH is required to locate Codex"))?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if let Ok(canonical) = fs::canonicalize(candidate)
            && canonical_secure_file(&canonical, true).is_ok()
        {
            return Ok(canonical);
        }
    }
    Err(BridgeError::invalid_config("codex was not found on PATH"))
}

fn nonempty_environment(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}
