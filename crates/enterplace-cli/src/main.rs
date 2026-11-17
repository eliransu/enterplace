//! The `enterplace` binary. One binary runs the server and the command line.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    enterplace_cli::run(&args).await
}
