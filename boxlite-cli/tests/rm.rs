use predicates::prelude::*;

mod common;

#[test]
fn test_rm_single() {
    let mut ctx = common::boxlite();
    let name = "rm-single";

    ctx.cmd
        .args(["create", "--name", name, "alpine:latest"])
        .assert()
        .success();

    ctx.new_cmd()
        .args(["rm", name])
        .assert()
        .success()
        .stdout(predicate::str::contains(name));
}

#[test]
fn test_rm_force_running() {
    let mut ctx = common::boxlite();
    let name = "rm-force";

    ctx.cmd
        .args(["run", "-d", "--name", name, "alpine:latest", "sleep", "300"])
        .assert()
        .success();

    // Without --force should fail
    ctx.new_cmd()
        .args(["rm", name])
        .assert()
        .failure();

    // With --force should succeed
    ctx.new_cmd()
        .args(["rm", "--force", name])
        .assert()
        .success()
        .stdout(predicate::str::contains(name));
}

#[test]
fn test_rm_all() {
    let mut ctx = common::boxlite();

    ctx.cmd
        .args(["create", "--name", "rm-all-1", "alpine:latest"])
        .assert()
        .success();

    ctx.new_cmd()
        .args(["create", "--name", "rm-all-2", "alpine:latest"])
        .assert()
        .success();

    ctx.new_cmd()
        .args(["rm", "--all"])
        .assert()
        .success();

    ctx.new_cmd()
        .args(["list", "-a", "-q"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_rm_unknown() {
    let mut ctx = common::boxlite();
    ctx.cmd.args(["rm", "non-existent-box-id"]);
    ctx.cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
