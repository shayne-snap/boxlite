use predicates::prelude::*;

mod common;

fn cleanup(ctx: &common::TestContext, name: &str) {
    let mut cmd = ctx.new_cmd();
    let _ = cmd.args(["rm", name, "--force"]).ok();
}

#[test]
fn test_create_basic() {
    let mut ctx = common::boxlite();
    ctx.cmd
        .arg("create")
        .arg("alpine:latest")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[0-9A-Z]{26}\n$").unwrap());
}

#[test]
fn test_create_named() {
    let name = "boxlite_create_named";
    let mut ctx = common::boxlite();
    cleanup(&ctx, name);
    ctx.cmd
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("alpine:latest")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[0-9A-Z]{26}\n$").unwrap());

    let mut cmd_dup = ctx.new_cmd();
    cmd_dup
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("alpine:latest")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    cleanup(&ctx, name);
}

#[test]
fn test_create_with_resources() {
    let name = "boxlite_create_resources";
    let mut ctx = common::boxlite();
    cleanup(&ctx, name);

    ctx.cmd
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("--cpus")
        .arg("1")
        .arg("--memory")
        .arg("128")
        .arg("--env")
        .arg("TEST_VAR=1")
        .arg("--workdir")
        .arg("/tmp")
        .arg("alpine:latest")
        .assert()
        .success();

    cleanup(&ctx, name);
}
