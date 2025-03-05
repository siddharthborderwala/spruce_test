use tracing_subscriber::EnvFilter;

/// Set up logging with custom filter that focuses on key events
pub fn setup_default_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in debug or release mode
    // In debug builds: log info, debug & error levels
    // In release builds: log only info & error levels
    let default_level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };

    // Allow overriding via RUST_LOG environment variable
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();

    Ok(())
}
