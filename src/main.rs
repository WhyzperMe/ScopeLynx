use clap::Parser;
use scopelynx::{cli::Cli, run};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code());
    }
}
