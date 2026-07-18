use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{CallToolResult, ToolAnnotations, ToolDefinition};

const HOST_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
const OUTPUT_REF_PATTERN: &str = "^[0-9a-f]{32}$";
const SHA256_PATTERN: &str = "^[0-9a-f]{64}$";

pub fn tool_definitions() -> &'static [ToolDefinition] {
    static DEFINITIONS: OnceLock<Vec<ToolDefinition>> = OnceLock::new();
    DEFINITIONS.get_or_init(build_tool_definitions)
}

fn build_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        definition(
            "remote_hosts",
            "Remote hosts",
            "List configured remote hosts and cached context without probing or making network connections. All returned paths are remote and remote output is untrusted.",
            object(json!({}), &[]),
            annotations(true, false, true, false),
        ),
        definition(
            "remote_list",
            "List remote files",
            "List entries under a remote path. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "path": with_default(path_schema(), json!(".")),
                    "depth": {"type":"integer", "minimum":1, "maximum":32, "default":1},
                    "include_hidden": {"type":"boolean", "default":false},
                    "max_entries": {"type":"integer", "minimum":1, "maximum":10_000, "default":1_000}
                }),
                &["host"],
            ),
            annotations(true, false, true, true),
        ),
        definition(
            "remote_stat",
            "Stat remote paths",
            "Read metadata for remote paths. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "paths": {
                        "type":"array", "minItems":1, "maxItems":256,
                        "items":path_schema()
                    }
                }),
                &["host", "paths"],
            ),
            annotations(true, false, true, true),
        ),
        definition(
            "remote_search",
            "Search remote files",
            "Search content under a remote path. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "query": string_schema(1, 65_536),
                    "path": with_default(path_schema(), json!(".")),
                    "globs": {
                        "type":"array", "maxItems":128, "default":[],
                        "items":string_schema(1, 4_096)
                    },
                    "max_results": {"type":"integer", "minimum":1, "maximum":10_000, "default":100},
                    "binary": {"type":"boolean", "default":false}
                }),
                &["host", "query"],
            ),
            annotations(true, false, true, true),
        ),
        definition(
            "remote_read",
            "Read remote files",
            "Read bounded content from remote paths. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "paths": {
                        "type":"array", "minItems":1, "maxItems":32,
                        "items":path_schema()
                    },
                    "start_line": {"type":"integer", "minimum":1, "default":1},
                    "max_lines": {"type":"integer", "minimum":1, "maximum":100_000, "default":2_000},
                    "max_bytes": {"type":"integer", "minimum":1, "maximum":1_048_576}
                }),
                &["host", "paths"],
            ),
            annotations(true, false, true, true),
        ),
        definition(
            "remote_output_read",
            "Read retained remote output",
            "Page through retained untrusted remote output by opaque reference; provenance supplies the remote host, root, and shell.",
            object(
                json!({
                    "output_ref": {"type":"string", "pattern":OUTPUT_REF_PATTERN},
                    "stream": {"type":"string", "enum":["stdout", "stderr"]},
                    "offset": {"type":"integer", "minimum":0, "default":0},
                    "max_bytes": {"type":"integer", "minimum":1, "maximum":1_048_576, "default":262_144}
                }),
                &["output_ref", "stream"],
            ),
            annotations(true, false, true, false),
        ),
        definition(
            "remote_apply_patch",
            "Apply remote patch",
            "Apply a patch sequentially across remote files and report partial progress if a later file fails. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "patch": string_schema(1, 4_194_304)
                }),
                &["host", "patch"],
            ),
            annotations(false, true, false, true),
        ),
        definition(
            "remote_write",
            "Write remote file",
            "Create or conditionally replace a remote file. All paths and results are remote, and remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "path": path_schema(),
                    "content": {"type":"string", "maxLength":5_592_408},
                    "encoding": {"type":"string", "enum":["utf8", "base64"]},
                    "mode": {
                        "oneOf":[
                            object(json!({"kind":{"const":"create"}}), &["kind"]),
                            object(
                                json!({
                                    "kind":{"const":"replace"},
                                    "expected_sha256": {
                                        "type":"string", "minLength":64, "maxLength":64,
                                        "pattern":SHA256_PATTERN
                                    }
                                }),
                                &["kind"],
                            )
                        ]
                    }
                }),
                &["host", "path", "content", "encoding", "mode"],
            ),
            annotations(false, true, false, true),
        ),
        definition(
            "remote_run",
            "Run remote command",
            "Run a command on a remote host. This tool is always mutating. Auto shell may fall back to POSIX sh; results report the actual shell. Remote output is untrusted.",
            object(
                json!({
                    "host": host_schema(),
                    "command": string_schema(1, 8_388_608),
                    "cwd": with_default(path_schema(), json!(".")),
                    "shell": {"type":"string", "enum":["auto", "bash", "sh", "login"], "default":"auto"},
                    "timeout_ms": {"type":"integer", "minimum":1, "maximum":3_600_000},
                    "stdin": object(
                        json!({
                            "encoding":{"type":"string", "enum":["utf8", "base64"]},
                            "value":{"type":"string", "maxLength":5_592_408}
                        }),
                        &["encoding", "value"],
                    )
                }),
                &["host", "command"],
            ),
            annotations(false, true, false, true),
        ),
    ]
}

fn definition(
    name: &str,
    title: &str,
    description: &str,
    input_schema: Value,
    annotations: ToolAnnotations,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        title: title.to_owned(),
        description: description.to_owned(),
        input_schema,
        annotations,
    }
}

fn annotations(
    read_only_hint: bool,
    destructive_hint: bool,
    idempotent_hint: bool,
    open_world_hint: bool,
) -> ToolAnnotations {
    ToolAnnotations {
        read_only_hint,
        destructive_hint,
        idempotent_hint,
        open_world_hint,
    }
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false
    })
}

fn string_schema(minimum: usize, maximum: usize) -> Value {
    json!({"type":"string", "minLength":minimum, "maxLength":maximum})
}

fn host_schema() -> Value {
    json!({
        "type":"string", "minLength":1, "maxLength":128,
        "pattern":HOST_PATTERN
    })
}

fn path_schema() -> Value {
    string_schema(1, 65_536)
}

fn with_default(mut schema: Value, default: Value) -> Value {
    schema
        .as_object_mut()
        .expect("schema helpers always construct objects")
        .insert("default".to_owned(), default);
    schema
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsArgs {}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    host: String,
    path: Option<String>,
    depth: Option<u32>,
    include_hidden: Option<bool>,
    max_entries: Option<usize>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatArgs {
    host: String,
    paths: Vec<String>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    host: String,
    query: String,
    path: Option<String>,
    #[serde(default)]
    globs: Vec<String>,
    max_results: Option<usize>,
    binary: Option<bool>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    host: String,
    paths: Vec<String>,
    start_line: Option<u64>,
    max_lines: Option<u64>,
    max_bytes: Option<usize>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputReadArgs {
    output_ref: String,
    stream: ToolStream,
    #[serde(default)]
    offset: u64,
    max_bytes: Option<usize>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyPatchArgs {
    host: String,
    patch: String,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    host: String,
    path: String,
    content: String,
    encoding: ToolEncoding,
    mode: ToolWriteMode,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    host: String,
    command: String,
    cwd: Option<String>,
    #[serde(default)]
    shell: ToolRunShell,
    timeout_ms: Option<u64>,
    stdin: Option<ToolEncodedInput>,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ToolEncoding {
    Utf8,
    Base64,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ToolStream {
    Stdout,
    Stderr,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ToolRunShell {
    #[default]
    Auto,
    Bash,
    Sh,
    Login,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolEncodedInput {
    encoding: ToolEncoding,
    value: String,
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum ToolWriteMode {
    Create {},
    Replace { expected_sha256: Option<String> },
}

#[allow(dead_code, reason = "Task 7 consumes the typed arguments")]
#[derive(Debug)]
enum ParsedToolArguments {
    Hosts(HostsArgs),
    List(ListArgs),
    Stat(StatArgs),
    Search(SearchArgs),
    Read(ReadArgs),
    OutputRead(OutputReadArgs),
    ApplyPatch(ApplyPatchArgs),
    Write(WriteArgs),
    Run(RunArgs),
}

#[derive(Debug, Clone, Copy)]
enum ArgumentValidationCategory {
    Shape,
    Constraint,
}

#[allow(dead_code, reason = "Task 7 dispatches parsed arguments")]
fn parse_tool_arguments(
    name: &str,
    arguments: Value,
) -> Result<ParsedToolArguments, CallToolResult> {
    if !arguments.is_object() {
        return Err(invalid_arguments(name, ArgumentValidationCategory::Shape));
    }
    let parsed = match name {
        "remote_hosts" => deserialize(arguments).map(ParsedToolArguments::Hosts),
        "remote_list" => deserialize(arguments).map(ParsedToolArguments::List),
        "remote_stat" => deserialize(arguments).map(ParsedToolArguments::Stat),
        "remote_search" => deserialize(arguments).map(ParsedToolArguments::Search),
        "remote_read" => deserialize(arguments).map(ParsedToolArguments::Read),
        "remote_output_read" => deserialize(arguments).map(ParsedToolArguments::OutputRead),
        "remote_apply_patch" => deserialize(arguments).map(ParsedToolArguments::ApplyPatch),
        "remote_write" => deserialize(arguments).map(ParsedToolArguments::Write),
        "remote_run" => deserialize(arguments).map(ParsedToolArguments::Run),
        _ => return Err(invalid_arguments(name, ArgumentValidationCategory::Shape)),
    }
    .map_err(|()| invalid_arguments(name, ArgumentValidationCategory::Shape))?;

    validate_parsed_arguments(&parsed).map_err(|category| invalid_arguments(name, category))?;
    Ok(parsed)
}

fn deserialize<T: for<'de> Deserialize<'de>>(arguments: Value) -> Result<T, ()> {
    serde_json::from_value(arguments).map_err(|_| ())
}

fn validate_parsed_arguments(
    arguments: &ParsedToolArguments,
) -> Result<(), ArgumentValidationCategory> {
    use ArgumentValidationCategory::Constraint;
    match arguments {
        ParsedToolArguments::Hosts(_) => Ok(()),
        ParsedToolArguments::List(arguments) => {
            validate_host(&arguments.host)?;
            validate_optional_path(arguments.path.as_deref())?;
            validate_optional_range(arguments.depth, 1, 32)?;
            validate_optional_range(arguments.max_entries, 1, 10_000)
        }
        ParsedToolArguments::Stat(arguments) => {
            validate_host(&arguments.host)?;
            validate_paths(&arguments.paths, 256)
        }
        ParsedToolArguments::Search(arguments) => {
            validate_host(&arguments.host)?;
            validate_chars(&arguments.query, 1, 65_536)?;
            validate_optional_path(arguments.path.as_deref())?;
            if arguments.globs.len() > 128 {
                return Err(Constraint);
            }
            for glob in &arguments.globs {
                validate_chars(glob, 1, 4_096)?;
            }
            validate_optional_range(arguments.max_results, 1, 10_000)
        }
        ParsedToolArguments::Read(arguments) => {
            validate_host(&arguments.host)?;
            validate_paths(&arguments.paths, 32)?;
            validate_optional_minimum(arguments.start_line, 1)?;
            validate_optional_range(arguments.max_lines, 1, 100_000)?;
            validate_optional_range(arguments.max_bytes, 1, 1_048_576)
        }
        ParsedToolArguments::OutputRead(arguments) => {
            if !is_lower_hex(&arguments.output_ref, 32) {
                return Err(Constraint);
            }
            validate_optional_range(arguments.max_bytes, 1, 1_048_576)
        }
        ParsedToolArguments::ApplyPatch(arguments) => {
            validate_host(&arguments.host)?;
            validate_chars(&arguments.patch, 1, 4_194_304)
        }
        ParsedToolArguments::Write(arguments) => {
            validate_host(&arguments.host)?;
            validate_path(&arguments.path)?;
            validate_chars(&arguments.content, 0, 5_592_408)?;
            if let ToolWriteMode::Replace {
                expected_sha256: Some(expected_sha256),
            } = &arguments.mode
                && !is_lower_hex(expected_sha256, 64)
            {
                return Err(Constraint);
            }
            Ok(())
        }
        ParsedToolArguments::Run(arguments) => {
            validate_host(&arguments.host)?;
            validate_chars(&arguments.command, 1, 8_388_608)?;
            validate_optional_path(arguments.cwd.as_deref())?;
            validate_optional_range(arguments.timeout_ms, 1, 3_600_000)?;
            if let Some(stdin) = &arguments.stdin {
                validate_chars(&stdin.value, 0, 5_592_408)?;
            }
            Ok(())
        }
    }
}

fn validate_host(host: &str) -> Result<(), ArgumentValidationCategory> {
    use ArgumentValidationCategory::Constraint;
    if host.is_empty() || host.len() > 128 {
        return Err(Constraint);
    }
    let mut bytes = host.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Constraint);
    }
    Ok(())
}

fn validate_paths(paths: &[String], maximum: usize) -> Result<(), ArgumentValidationCategory> {
    use ArgumentValidationCategory::Constraint;
    if paths.is_empty() || paths.len() > maximum {
        return Err(Constraint);
    }
    paths.iter().try_for_each(|path| validate_path(path))
}

fn validate_optional_path(path: Option<&str>) -> Result<(), ArgumentValidationCategory> {
    path.map_or(Ok(()), validate_path)
}

fn validate_path(path: &str) -> Result<(), ArgumentValidationCategory> {
    validate_chars(path, 1, 65_536)
}

fn validate_chars(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ArgumentValidationCategory> {
    use ArgumentValidationCategory::Constraint;
    let count = value.chars().count();
    if (minimum..=maximum).contains(&count) {
        Ok(())
    } else {
        Err(Constraint)
    }
}

fn validate_optional_minimum<T>(
    value: Option<T>,
    minimum: T,
) -> Result<(), ArgumentValidationCategory>
where
    T: PartialOrd,
{
    use ArgumentValidationCategory::Constraint;
    if value.is_some_and(|value| value < minimum) {
        Err(Constraint)
    } else {
        Ok(())
    }
}

fn validate_optional_range<T>(
    value: Option<T>,
    minimum: T,
    maximum: T,
) -> Result<(), ArgumentValidationCategory>
where
    T: PartialOrd,
{
    use ArgumentValidationCategory::Constraint;
    if value.is_some_and(|value| value < minimum || value > maximum) {
        Err(Constraint)
    } else {
        Ok(())
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_arguments(name: &str, _: ArgumentValidationCategory) -> CallToolResult {
    let action = match name {
        "remote_hosts" => "provide an empty object for remote_hosts",
        "remote_list" => "provide a valid host and bounded remote_list options",
        "remote_stat" => "provide a valid host and 1 to 256 remote paths",
        "remote_search" => "provide a valid host, nonempty query, and bounded search options",
        "remote_read" => "provide a valid host, 1 to 32 remote paths, and bounded read options",
        "remote_output_read" => {
            "provide a 32-character lowercase output reference, stream, and bounded page size"
        }
        "remote_apply_patch" => "provide a valid host and nonempty bounded patch",
        "remote_write" => {
            "provide a valid host, remote path, encoded content, and closed write mode"
        }
        "remote_run" => "provide a valid host, nonempty command, and bounded closed run options",
        _ => "provide valid tool arguments",
    };
    CallToolResult::invalid_argument(action)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::parse_tool_arguments;

    fn assert_valid(name: &str, arguments: Value) {
        assert!(
            parse_tool_arguments(name, arguments).is_ok(),
            "{name} rejected valid arguments"
        );
    }

    fn assert_invalid(name: &str, arguments: Value) {
        let result = parse_tool_arguments(name, arguments);
        assert!(result.is_err(), "{name} accepted invalid arguments");
        assert!(result.err().unwrap().is_error);
    }

    #[test]
    fn task8_arguments_accept_one_valid_closed_object_per_tool() {
        let valid = [
            ("remote_hosts", json!({})),
            ("remote_list", json!({"host":"dev"})),
            ("remote_stat", json!({"host":"dev", "paths":["a"]})),
            ("remote_search", json!({"host":"dev", "query":"needle"})),
            ("remote_read", json!({"host":"dev", "paths":["a"]})),
            (
                "remote_output_read",
                json!({"output_ref":"a".repeat(32), "stream":"stdout"}),
            ),
            (
                "remote_apply_patch",
                json!({"host":"dev", "patch":"*** Begin Patch\n*** End Patch"}),
            ),
            (
                "remote_write",
                json!({
                    "host":"dev", "path":"a", "content":"", "encoding":"utf8",
                    "mode":{"kind":"create"}
                }),
            ),
            ("remote_run", json!({"host":"dev", "command":"true"})),
        ];
        for (name, arguments) in valid {
            assert_valid(name, arguments);
        }

        let replace = json!({
            "host":"dev",
            "path":"a",
            "content":"eA==",
            "encoding":"base64",
            "mode":{"kind":"replace","expected_sha256":"0".repeat(64)}
        });
        assert_valid("remote_write", replace);
    }

    #[test]
    fn task8_arguments_reject_missing_required_fields_and_wrong_types() {
        for (name, missing, wrong_type) in [
            ("remote_list", json!({}), json!({"host":1})),
            (
                "remote_stat",
                json!({"host":"dev"}),
                json!({"host":"dev", "paths":"a"}),
            ),
            (
                "remote_search",
                json!({"host":"dev"}),
                json!({"host":"dev", "query":true}),
            ),
            (
                "remote_read",
                json!({"host":"dev"}),
                json!({"host":"dev", "paths":{}}),
            ),
            (
                "remote_output_read",
                json!({"output_ref":"a".repeat(32)}),
                json!({"output_ref":"a".repeat(32), "stream":1}),
            ),
            (
                "remote_apply_patch",
                json!({"host":"dev"}),
                json!({"host":"dev", "patch":[]}),
            ),
            (
                "remote_write",
                json!({"host":"dev", "path":"a"}),
                json!({
                    "host":"dev", "path":"a", "content":"", "encoding":1,
                    "mode":{"kind":"create"}
                }),
            ),
            (
                "remote_run",
                json!({"host":"dev"}),
                json!({"host":"dev", "command":[]}),
            ),
        ] {
            assert_invalid(name, missing);
            assert_invalid(name, wrong_type);
        }
        assert_invalid("remote_hosts", json!([]));
    }

    #[test]
    fn task8_arguments_reject_unknown_root_and_nested_fields() {
        let valid = [
            ("remote_hosts", json!({})),
            ("remote_list", json!({"host":"dev"})),
            ("remote_stat", json!({"host":"dev", "paths":["a"]})),
            ("remote_search", json!({"host":"dev", "query":"needle"})),
            ("remote_read", json!({"host":"dev", "paths":["a"]})),
            (
                "remote_output_read",
                json!({"output_ref":"a".repeat(32), "stream":"stdout"}),
            ),
            ("remote_apply_patch", json!({"host":"dev", "patch":"patch"})),
            (
                "remote_write",
                json!({
                    "host":"dev", "path":"a", "content":"", "encoding":"utf8",
                    "mode":{"kind":"create"}
                }),
            ),
            ("remote_run", json!({"host":"dev", "command":"true"})),
        ];
        for (name, mut arguments) in valid {
            arguments["extra"] = json!(true);
            assert_invalid(name, arguments);
        }

        assert_invalid(
            "remote_write",
            json!({
                "host":"dev", "path":"a", "content":"", "encoding":"utf8",
                "mode":{"kind":"create", "extra":true}
            }),
        );
        let bad_nested = json!({
            "host":"dev",
            "command":"true",
            "stdin":{"encoding":"utf8","value":"","extra":true}
        });
        assert_invalid("remote_run", bad_nested);
    }

    #[test]
    fn task8_arguments_enforce_all_advertised_scalar_bounds_and_patterns() {
        for host in [
            "".to_owned(),
            "-dev".to_owned(),
            "dev!".to_owned(),
            "a".repeat(129),
        ] {
            assert_invalid("remote_list", json!({"host":host}));
        }
        assert_valid("remote_list", json!({"host":"a".repeat(128)}));

        for arguments in [
            json!({"host":"dev", "path":""}),
            json!({"host":"dev", "path":"a".repeat(65_537)}),
            json!({"host":"dev", "depth":0}),
            json!({"host":"dev", "depth":33}),
            json!({"host":"dev", "max_entries":0}),
            json!({"host":"dev", "max_entries":10_001}),
        ] {
            assert_invalid("remote_list", arguments);
        }

        for arguments in [
            json!({"host":"dev", "paths":[]}),
            json!({"host":"dev", "paths":vec!["a"; 257]}),
            json!({"host":"dev", "paths":[""]}),
        ] {
            assert_invalid("remote_stat", arguments);
        }

        for arguments in [
            json!({"host":"dev", "query":""}),
            json!({"host":"dev", "query":"q".repeat(65_537)}),
            json!({"host":"dev", "query":"q", "globs":vec!["a"; 129]}),
            json!({"host":"dev", "query":"q", "globs":[""]}),
            json!({"host":"dev", "query":"q", "globs":["a".repeat(4_097)]}),
            json!({"host":"dev", "query":"q", "max_results":0}),
            json!({"host":"dev", "query":"q", "max_results":10_001}),
        ] {
            assert_invalid("remote_search", arguments);
        }

        for arguments in [
            json!({"host":"dev", "paths":[]}),
            json!({"host":"dev", "paths":vec!["a"; 33]}),
            json!({"host":"dev", "paths":["a"], "start_line":0}),
            json!({"host":"dev", "paths":["a"], "max_lines":0}),
            json!({"host":"dev", "paths":["a"], "max_lines":100_001}),
            json!({"host":"dev", "paths":["a"], "max_bytes":0}),
            json!({"host":"dev", "paths":["a"], "max_bytes":1_048_577}),
        ] {
            assert_invalid("remote_read", arguments);
        }

        for arguments in [
            json!({"output_ref":"A".repeat(32), "stream":"stdout"}),
            json!({"output_ref":"a".repeat(31), "stream":"stdout"}),
            json!({"output_ref":"a".repeat(32), "stream":"both"}),
            json!({"output_ref":"a".repeat(32), "stream":"stdout", "max_bytes":0}),
            json!({"output_ref":"a".repeat(32), "stream":"stdout", "max_bytes":1_048_577}),
        ] {
            assert_invalid("remote_output_read", arguments);
        }

        assert_invalid("remote_apply_patch", json!({"host":"dev", "patch":""}));
        assert_invalid(
            "remote_apply_patch",
            json!({"host":"dev", "patch":"x".repeat(4_194_305)}),
        );

        assert_invalid(
            "remote_write",
            json!({
                "host":"dev", "path":"a", "content":"x".repeat(5_592_409),
                "encoding":"utf8", "mode":{"kind":"create"}
            }),
        );
        assert_invalid(
            "remote_write",
            json!({
                "host":"dev", "path":"a", "content":"", "encoding":"hex",
                "mode":{"kind":"create"}
            }),
        );
        assert_invalid(
            "remote_write",
            json!({
                "host":"dev", "path":"a", "content":"", "encoding":"utf8",
                "mode":{"kind":"append"}
            }),
        );
        for hash in ["A".repeat(64), "a".repeat(63)] {
            assert_invalid(
                "remote_write",
                json!({
                    "host":"dev", "path":"a", "content":"", "encoding":"utf8",
                    "mode":{"kind":"replace", "expected_sha256":hash}
                }),
            );
        }

        for arguments in [
            json!({"host":"dev", "command":""}),
            json!({"host":"dev", "command":"x".repeat(8_388_609)}),
            json!({"host":"dev", "command":"true", "cwd":""}),
            json!({"host":"dev", "command":"true", "shell":"fish"}),
            json!({"host":"dev", "command":"true", "timeout_ms":0}),
            json!({"host":"dev", "command":"true", "timeout_ms":3_600_001}),
            json!({
                "host":"dev", "command":"true",
                "stdin":{"encoding":"hex", "value":""}
            }),
            json!({
                "host":"dev", "command":"true",
                "stdin":{"encoding":"utf8", "value":"x".repeat(5_592_409)}
            }),
        ] {
            assert_invalid("remote_run", arguments);
        }
    }

    #[test]
    fn task8_arguments_never_echo_rejected_values_or_serde_diagnostics() {
        let secret = "REJECTED_SECRET_VALUE";
        let error = parse_tool_arguments(
            "remote_run",
            json!({"host":"dev", "command":secret, "extra":true}),
        )
        .err()
        .unwrap();
        let serialized = serde_json::to_string(&error).unwrap();
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("unknown field"));
        assert!(serialized.contains("provide a valid host"));
    }
}
