//! Running a child process under a wall clock, with capped capture.
//!
//! Shared by every backend, because the two §14.4 clauses it implements — "a wall-clock timeout
//! (report `errored` when it fires)" and "cap captured output so a job can't OOM the runner by
//! flooding logs" — are host-side properties that hold no matter what the sandbox is. The container
//! backend runs the *runtime CLI* through here; the local backend runs the job directly.
//!
//! The capture is driven while the child runs, never by buffering the pipes and reading at exit: an
//! OS pipe buffer is finite, so a job that prints more than the buffer would block forever waiting for
//! a reader, and a job that prints gigabytes would otherwise be read into memory in one go. Reading
//! concurrently into a capped [`OutputCapture`] is what makes the cap actually bound our memory.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout};

use crate::capture::OutputCapture;
use crate::sandbox::{ExecOutcome, ExecStatus, SandboxError};

/// Build a `tokio` command from argv with a scrubbed environment.
///
/// The signature is the point: argv in, argv out. There is no overload taking a command *string*, so
/// no caller in this crate can interpolate a user string into a host command line (D§7.2: "No raw
/// shell on any host, ever").
pub fn command_from_argv(argv: &[String], env: &[(String, String)]) -> Result<tokio::process::Command, SandboxError> {
    let Some(program) = argv.first() else { return Err(SandboxError::EmptyArgv) };
    if program.trim().is_empty() {
        return Err(SandboxError::EmptyArgv);
    }
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(&argv[1..]);
    // Drop the node's whole environment first: §14.2 wants an allowlist, and an allowlist built by
    // subtraction is a deny-list that fails open the next time someone exports something.
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    Ok(cmd)
}

/// Run a spawned child to completion (or to the wall clock), capturing into `capture`.
///
/// On expiry the child is killed and the outcome is [`ExecStatus::TimedOut`], which the node agent
/// maps to `StepOutcome::Errored` — never `Failed`. §14.4 and spec §7 are explicit: we stopped the
/// job, so we do not have a statement about the code.
pub async fn run_to_completion(
    mut child: Child,
    timeout: Duration,
    capture: &mut OutputCapture,
) -> Result<ExecOutcome, SandboxError> {
    let started = Instant::now();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let result = {
        let pump_and_wait = async {
            pump(&mut stdout, &mut stderr, capture).await?;
            child.wait().await
        };
        tokio::time::timeout(timeout, pump_and_wait).await
    };

    match result {
        Ok(Ok(status)) => {
            Ok(ExecOutcome { status: ExecStatus::from_exit(status), duration: started.elapsed() })
        }
        Ok(Err(e)) => Err(SandboxError::Io(e)),
        Err(_elapsed) => {
            // Kill, then reap, so we do not leave a zombie holding the sandbox open. Failure to kill
            // is logged rather than returned: the verdict is already decided (timeout → errored), and
            // the backend's `destroy` is the real teardown.
            if let Err(e) = child.start_kill() {
                tracing::warn!(error = %e, "could not signal a timed-out child");
            }
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "reaping a timed-out child failed"),
                Err(_) => tracing::warn!("timed-out child did not exit within 5s of being killed"),
            }
            Ok(ExecOutcome { status: ExecStatus::TimedOut, duration: started.elapsed() })
        }
    }
}

/// Read both pipes concurrently until each reaches EOF, feeding the capped capture.
async fn pump(
    stdout: &mut Option<ChildStdout>,
    stderr: &mut Option<ChildStderr>,
    capture: &mut OutputCapture,
) -> std::io::Result<()> {
    // stdout and stderr are interleaved into one capture on purpose: a test runner's failure lines and
    // its progress output only make sense in order, and one capture means one cap (§14.4) rather than
    // two budgets a job could spend twice.
    let mut obuf = vec![0u8; 16 * 1024];
    let mut ebuf = vec![0u8; 16 * 1024];

    enum Read {
        Out(usize),
        Err(usize),
    }

    loop {
        // The borrows of stdout/stderr end with this statement, which is what lets the match below
        // clear them on EOF. `AsyncReadExt::read` is cancel-safe, so the losing select branch loses
        // no bytes.
        let got = match (stdout.as_mut(), stderr.as_mut()) {
            (Some(o), Some(e)) => tokio::select! {
                r = o.read(&mut obuf) => Read::Out(r?),
                r = e.read(&mut ebuf) => Read::Err(r?),
            },
            (Some(o), None) => Read::Out(o.read(&mut obuf).await?),
            (None, Some(e)) => Read::Err(e.read(&mut ebuf).await?),
            (None, None) => break,
        };
        match got {
            Read::Out(0) => *stdout = None,
            Read::Out(n) => capture.push(&obuf[..n]),
            Read::Err(0) => *stderr = None,
            Read::Err(n) => capture.push(&ebuf[..n]),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::OutputCaps;

    fn env() -> Vec<(String, String)> {
        crate::env::base_env("/tmp")
    }

    #[tokio::test]
    async fn captures_both_streams_and_the_exit_code() {
        let mut cmd = command_from_argv(
            &["/bin/sh".into(), "-c".into(), "echo out; echo err 1>&2; exit 3".into()],
            &env(),
        )
        .unwrap();
        // NB: this is the *test harness* invoking a shell as the subject under test — the production
        // paths in this crate never construct `sh -c` (D§7.2).
        let mut cap = OutputCapture::new(OutputCaps::default());
        let outcome = run_to_completion(cmd.spawn().unwrap(), Duration::from_secs(30), &mut cap)
            .await
            .unwrap();
        assert_eq!(outcome.status, ExecStatus::Exited(3));
        let text = cap.finish().text();
        assert!(text.contains("out") && text.contains("err"));
    }

    #[tokio::test]
    async fn the_environment_is_the_allowlist_not_the_node_s() {
        std::env::set_var("HULL_NODE_TEST_LEAK", "should-not-appear");
        let mut cmd = command_from_argv(&["/usr/bin/env".into()], &env()).unwrap();
        let mut cap = OutputCapture::new(OutputCaps::default());
        run_to_completion(cmd.spawn().unwrap(), Duration::from_secs(30), &mut cap).await.unwrap();
        let text = cap.finish().text();
        assert!(!text.contains("should-not-appear"), "§14.2: the job environment is built, not inherited");
        assert!(text.contains("CI=true"));
        std::env::remove_var("HULL_NODE_TEST_LEAK");
    }

    #[tokio::test]
    async fn a_flooding_job_cannot_exhaust_our_memory() {
        // The pipe-blocking half of §14.4: if we did not read concurrently, this child would fill the
        // pipe buffer and hang; if we read without a cap, it would grow our heap without bound.
        let mut cmd = command_from_argv(
            &["/bin/sh".into(), "-c".into(), "i=0; while [ $i -lt 20000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done".into()],
            &env(),
        )
        .unwrap();
        let mut cap = OutputCapture::new(OutputCaps::new(4096, 1_000_000));
        let outcome = run_to_completion(cmd.spawn().unwrap(), Duration::from_secs(60), &mut cap)
            .await
            .unwrap();
        assert_eq!(outcome.status, ExecStatus::Exited(0));
        let out = cap.finish();
        assert!(out.truncated());
        assert!(out.bytes().len() <= 4096);
    }

    #[tokio::test]
    async fn the_wall_clock_kills_and_reports_timed_out() {
        let mut cmd = command_from_argv(&["/bin/sleep".into(), "30".into()], &env()).unwrap();
        let mut cap = OutputCapture::new(OutputCaps::default());
        let outcome = run_to_completion(cmd.spawn().unwrap(), Duration::from_millis(200), &mut cap)
            .await
            .unwrap();
        assert_eq!(outcome.status, ExecStatus::TimedOut);
        assert!(outcome.duration < Duration::from_secs(10));
    }

    #[test]
    fn empty_argv_never_reaches_the_host() {
        assert!(matches!(command_from_argv(&[], &env()), Err(SandboxError::EmptyArgv)));
        assert!(matches!(command_from_argv(&["  ".into()], &env()), Err(SandboxError::EmptyArgv)));
    }
}
