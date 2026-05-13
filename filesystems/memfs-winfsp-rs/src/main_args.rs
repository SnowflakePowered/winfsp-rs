use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "In-memory file system (port of winfsp memfs)", long_about = None)]
pub struct Args {
    /// Debug flags (-1 for all)
    #[arg(short = 'd', default_value_t = 0)]
    pub debug_flags: i32,

    /// Case-insensitive file names
    #[arg(short = 'i', default_value_t = false)]
    pub case_insensitive: bool,

    /// Flush and purge cache on cleanup
    #[arg(short = 'f', default_value_t = false)]
    pub flush_and_purge_on_cleanup: bool,

    /// FileInfo timeout (ms). Use u32::MAX (the default) to disable.
    #[arg(short = 't', default_value_t = u32::MAX)]
    pub file_info_timeout: u32,

    /// Maximum number of file nodes
    #[arg(short = 'n', default_value_t = 1024)]
    pub max_file_nodes: u32,

    /// Maximum file size in bytes
    #[arg(short = 's', default_value_t = 16 * 1024 * 1024)]
    pub max_file_size: u32,

    /// Maximum slow-I/O delay in milliseconds. Set to 0 (default) to disable.
    #[arg(short = 'M', default_value_t = 0)]
    pub slowio_max_delay: u32,

    /// Percent (0-100) of I/O calls that get a slow-I/O delay applied.
    #[arg(short = 'P', default_value_t = 0)]
    pub slowio_percent_delay: u32,

    /// Slow-I/O rarefy parameter: higher values bias toward shorter delays.
    #[arg(short = 'R', default_value_t = 0)]
    pub slowio_rarefy_delay: u32,

    /// File system name (reported to Windows)
    #[arg(short = 'F', long)]
    pub file_system_name: Option<String>,

    /// Root SDDL string
    #[arg(short = 'S', long)]
    pub root_sddl: Option<String>,

    /// UNC volume prefix
    #[arg(short = 'u', long)]
    pub volume_prefix: Option<String>,

    /// Mount point (e.g. `X:`, a directory path, or `*` for next free drive)
    #[arg(short = 'm', long)]
    pub mountpoint: Option<String>,
}
