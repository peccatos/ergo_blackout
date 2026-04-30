use std::process::Command;

#[test]
fn applies_and_restores_inside_network_namespace_when_enabled() {
    if std::env::var_os("ERGO_BLACKOUT_NETNS_TEST").is_none() {
        eprintln!("skipping privileged netns test; set ERGO_BLACKOUT_NETNS_TEST=1 to run it");
        return;
    }

    let binary = env!("CARGO_BIN_EXE_ergo_blackout");
    let script = format!(
        r#"{binary} blackout --apply \
&& nft list table inet ergo_blackout \
&& {binary} restore --apply \
&& ! nft list table inet ergo_blackout"#
    );

    let output = Command::new("unshare")
        .args(["-Urn", "sh", "-c", &script])
        .output()
        .expect("failed to run unshare-based netns test");

    assert!(
        output.status.success(),
        "netns test failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
