use predicates::prelude::*;

mod common;

fn cleanup(ctx: &common::TestContext, name: &str) {
    let mut cmd = ctx.new_cmd();
    let _ = cmd.args(["rm", name, "--force"]).ok();
}

#[test]
fn test_list_empty_or_header() {
    let mut ctx = common::boxlite();
    ctx.cmd
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("ID"))
        .stdout(predicate::str::contains("IMAGE"))
        .stdout(predicate::str::contains("STATUS"));
}

#[test]
fn test_list_lifecycle() {
    let name = "boxlite_list";
    let mut ctx = common::boxlite();
    cleanup(&ctx, name);

    let _ = ctx
        .cmd
        .args(["create", "--name", name, "alpine:latest"])
        .output();

    let mut list_cmd = ctx.new_cmd();
    list_cmd
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(name).not());

    let mut list_all = ctx.new_cmd();
    list_all
        .args(["list", "-a"])
        .assert()
        .success()
        .stdout(predicate::str::contains(name))
        .stdout(predicate::str::contains("Configured"));

    cleanup(&ctx, name);
}

#[test]
fn test_list_alias_ls() {
    let mut ctx = common::boxlite();
    ctx.cmd.arg("ls").assert().success();
}
