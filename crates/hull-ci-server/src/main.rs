//! The `hull-ci-server` binary. Configuration comes from the environment ([`hull_ci_server::config`]).
//!
//! ```bash
//! HULL_CI_SECRET=… HULL_CI_TRUSTED_TENANTS=acme hull-ci-server
//! ```
//!
//! Exit code 1 on any startup refusal, with the reason on stderr as well as in the log: a runner that
//! will not start must say why somewhere an operator is actually looking, and a `tracing` subscriber
//! configured by `RUST_LOG` is not that place if `RUST_LOG` filtered it out.

use hull_ci_server::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };

    match hull_ci_server::run(config).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(detail: &str) -> std::process::ExitCode {
    tracing::error!(error = detail, "hull-ci did not start");
    eprintln!("hull-ci: {detail}");
    std::process::ExitCode::FAILURE
}
