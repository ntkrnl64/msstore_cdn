use clap::Parser;
use eyre::{Context, Result};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument};

#[cfg(target_os = "windows")]
use native_windows_derive::NwgUi;
#[cfg(target_os = "windows")]
use native_windows_gui as nwg;
#[cfg(target_os = "windows")]
use native_windows_gui::NativeUi;

const TARGET_DOMAIN: &str = "tlu.dl.delivery.mp.microsoft.com";
const API_URL: &str = "https://qsl-api.krnl64.win/api/links/resolve-all";

#[derive(Debug, Clone)]
struct DnsSource {
    name: &'static str,
    domain: &'static str,
}

const DNS_SOURCES: &[DnsSource] = &[
    DnsSource {
        name: "China Telecom (CTCDN)",
        domain: "httpdns.ctdns.cn",
    },
    DnsSource {
        name: "Baidu Cloud (BDYDNS)",
        domain: "tlu.dl.delivery.mp.microsoft.com.a.bdydns.com",
    },
    DnsSource {
        name: "DNSE8 / Tencent Cloud",
        domain: "tlu.dl.delivery.mp.microsoft.com.cdn.dnse8.com",
    },
    DnsSource {
        name: "Kingsoft Cloud",
        domain: "tlu.dl.delivery.mp.microsoft.com.download.ks-cdn.com",
    },
    DnsSource {
        name: "XinLiu Cloud (CNGSLB)",
        domain: "wsdt-xlc.tlu.dl.delivery.mp.microsoft.com.z.cngslb.com",
    },
    DnsSource {
        name: "Fastly (International)",
        domain: "fg.microsoft.map.fastly.net",
    },
    DnsSource {
        name: "Akamai (International)",
        domain: "tlu.dl.delivery.mp.microsoft.com-c.edgesuite.net",
    },
    DnsSource {
        name: "GlobalCDN",
        domain: "cl-glcb907925.globalcdn.co",
    },
];

#[derive(Serialize)]
struct ApiRequest {
    productInput: String,
    market: String,
    locale: String,
    ring: String,
    identifierType: String,
    includeAppx: bool,
    includeNonAppx: bool,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    #[serde(rename = "appxPackages")]
    appx_packages: Vec<AppxPackage>,
}

#[derive(Deserialize, Debug, Clone)]
struct AppxPackage {
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "fileLink")]
    file_link: String,
}

#[cfg(windows)]
const NEWLINE: &str = "\r\n";
#[cfg(not(windows))]
const NEWLINE: &str = "\n";

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run without modifying the file
    #[arg(long)]
    dry_run: bool,

    /// Force GUI
    #[arg(short, long, default_value_t = false)]
    gui: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Custom input hosts file location
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Custom output hosts file location
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Index of the DNS source to use manually.
    #[arg(short = 's', long = "source", default_value_t = 0)]
    source_index: usize,

    /// Automatically select the fastest source
    #[arg(long, default_value_t = true)]
    auto: bool,

    /// Enable system proxy usage (Default: false)
    #[arg(long, default_value_t = false)]
    use_system_proxy: bool,
}

fn main() -> Result<()> {
    color_eyre::install().ok();

    let args_raw: Vec<String> = std::env::args().collect();
    let has_args = args_raw.len() > 1;

    #[cfg(target_os = "windows")]
    let double_clicked = is_double_clicked();
    #[cfg(not(target_os = "windows"))]
    let double_clicked = false;

    let args = Args::parse();

    let use_gui = (!has_args && double_clicked) || args.gui;

    if use_gui {
        run_gui_or_fallback()
    } else {
        run_cli_mode()
    }
}

fn run_gui_or_fallback() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        run_gui_mode()
    }
    #[cfg(not(target_os = "windows"))]
    {
        println!("GUI mode is only available on Windows.");
        run_cli_mode()
    }
}

fn run_cli_mode() -> Result<()> {
    let args = Args::parse();
    init_logging(args.debug);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async_main(args, None))
}

fn init_logging(debug_mode: bool) {
    let log_level = if debug_mode {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(debug_mode)
        .without_time()
        .init();
}

async fn async_main(mut args: Args, gui_logger: Option<Arc<Mutex<String>>>) -> Result<()> {
    let selected_source_domain = if args.auto {
        // Pass the proxy flag to the selection logic
        match run_auto_selection(gui_logger.clone(), args.use_system_proxy).await {
            Ok(domain) => {
                info!("Auto-selection winner: {}", domain);
                domain
            }
            Err(e) => {
                let err_msg = format!("Auto-selection failed: {}. Falling back to default.", e);
                error!("{}", err_msg);
                if let Some(logger) = &gui_logger {
                    if let Ok(mut guard) = logger.lock() {
                        guard.push_str(&err_msg);
                        guard.push_str(NEWLINE);
                    }
                }
                DNS_SOURCES[0].domain.to_string()
            }
        }
    } else {
        // Validation for manual index
        if args.source_index < DNS_SOURCES.len() {
            DNS_SOURCES[args.source_index].domain.to_string()
        } else {
            eprintln!("Invalid source index. Using default (0).");
            DNS_SOURCES[0].domain.to_string()
        }
    };

    core_logic(args, selected_source_domain, gui_logger).await
}

/// 自动选择逻辑
async fn run_auto_selection(
    gui_logger: Option<Arc<Mutex<String>>>,
    use_system_proxy: bool,
) -> Result<String> {
    macro_rules! log_msg {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            info!("{}", msg);
            if let Some(logger) = &gui_logger {
                if let Ok(mut guard) = logger.lock() {
                    guard.push_str(&msg);
                    guard.push_str(NEWLINE);
                }
            }
        }};
    }

    log_msg!("Starting auto-selection...");
    if use_system_proxy {
        log_msg!("Network: Using System Proxy");
    } else {
        log_msg!("Network: Direct Connection (No Proxy)");
    }
    log_msg!("Fetching file links from API...");

    // 1. Configure Client
    let mut client_builder = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .timeout(Duration::from_secs(10));

    // Disable proxy if not requested
    if !use_system_proxy {
        client_builder = client_builder.no_proxy();
    }

    let client = client_builder.build()?;

    // 2. Fetch Links
    let payload = ApiRequest {
        productInput: "9WZDNCRD29V9".to_string(),
        market: "US".to_string(),
        locale: "en-US".to_string(),
        ring: "Retail".to_string(),
        identifierType: "ProductID".to_string(),
        includeAppx: true,
        includeNonAppx: true,
    };

    let resp = client
        .post(API_URL)
        .json(&payload)
        .send()
        .await
        .context("Failed to connect to API")?;

    let api_data: ApiResponse = resp.json().await.context("Failed to parse API response")?;

    // 3. Select a test file
    let test_package = api_data
        .appx_packages
        .iter()
        .find(|p| p.file_name.contains("VCLibs") && p.file_name.contains("x64"))
        .or_else(|| api_data.appx_packages.last())
        .ok_or_else(|| eyre::eyre!("No packages found in API response"))?;

    log_msg!("Test file selected: {}", test_package.file_name);

    // Parse URL to get path
    let url = reqwest::Url::parse(&test_package.file_link)?;
    let path = url.path();
    let query = url.query().unwrap_or("");
    let full_path = if query.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, query)
    };

    // 4. Benchmark in parallel
    log_msg!("Benchmarking {} sources...", DNS_SOURCES.len());

    let futures = DNS_SOURCES.iter().map(|source| {
        let client = client.clone();
        let target_host = TARGET_DOMAIN.to_string();
        let resource_path = full_path.clone();
        let source_name = source.name;
        let source_domain = source.domain;

        async move {
            // Resolve IP for the CDN source domain
            let ip_list = match resolve_ip(source_domain).await {
                Ok(ips) => ips,
                Err(e) => {
                    debug!("[{}] DNS resolution failed: {}", source_name, e);
                    return (source_name, source_domain, None, 0);
                }
            };

            // Pick first IPv4
            let target_ip = match ip_list.iter().find(|ip| ip.is_ipv4()) {
                Some(ip) => *ip,
                None => {
                    debug!(
                        "[{}] No IPv4 address found in list: {:?}",
                        source_name, ip_list
                    );
                    return (source_name, source_domain, None, 0);
                }
            };

            debug!(
                "[{}] Resolved IP: {} -> {}",
                source_name, source_domain, target_ip
            );

            // Construct URL using IP to force connection to specific CDN
            let test_url = format!("http://{}{}", target_ip, resource_path);

            let start_download = Instant::now();

            // Execute Request
            let req = client
                .get(&test_url)
                .header("Host", &target_host)
                .send()
                .await;

            match req {
                Ok(response) => {
                    if !response.status().is_success() {
                        debug!("[{}] HTTP Error Status: {}", source_name, response.status());
                        return (source_name, source_domain, None, 0);
                    }

                    let content_length = response.content_length().unwrap_or(0);

                    // Download payload
                    match response.bytes().await {
                        Ok(bytes) => {
                            let duration = start_download.elapsed();
                            let size = bytes.len() as u64;

                            // Check size consistency
                            if size == 0 {
                                debug!("[{}] Downloaded 0 bytes.", source_name);
                                return (source_name, source_domain, None, 0);
                            }

                            if content_length > 0 {
                                let diff = (size as i64 - content_length as i64).abs();
                                if diff > 10240 {
                                    debug!(
                                        "[{}] Size mismatch! Expected: {}, Got: {}, Diff: {}",
                                        source_name, content_length, size, diff
                                    );
                                    return (source_name, source_domain, None, 0);
                                }
                            }

                            debug!(
                                "[{}] Success. Time: {:.2?} Size: {}",
                                source_name, duration, size
                            );
                            (source_name, source_domain, Some(duration), size)
                        }
                        Err(e) => {
                            debug!("[{}] Download stream failed: {}", source_name, e);
                            (source_name, source_domain, None, 0)
                        }
                    }
                }
                Err(e) => {
                    debug!("[{}] Connection failed: {}", source_name, e);
                    (source_name, source_domain, None, 0)
                }
            }
        }
    });

    // Run up to 8 parallel requests
    let results: Vec<_> = futures::stream::iter(futures)
        .buffer_unordered(8)
        .collect()
        .await;

    // 5. Analyze results
    let mut valid_results: Vec<_> = results
        .into_iter()
        .filter_map(|(name, domain, duration, size)| {
            if let Some(d) = duration {
                Some((name, domain, d, size))
            } else {
                None
            }
        })
        .collect();

    // Sort by duration (asc)
    valid_results.sort_by_key(|k| k.2);

    for (name, _, duration, size) in &valid_results {
        log_msg!("  [{}] Time: {:.2?} | Size: {} bytes", name, duration, size);
    }

    if let Some(winner) = valid_results.first() {
        log_msg!("Winner: {} ({:.2?})", winner.0, winner.2);
        Ok(winner.1.to_string())
    } else {
        Err(eyre::eyre!("All CDN sources failed speed test."))
    }
}

/// The core logic shared by both CLI and GUI
async fn core_logic(
    args: Args,
    source_domain: String,
    gui_logger: Option<Arc<Mutex<String>>>,
) -> Result<()> {
    // Helper macro to log to both tracing and GUI buffer
    macro_rules! log_msg {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            info!("{}", msg);
            if let Some(logger) = &gui_logger {
                if let Ok(mut guard) = logger.lock() {
                    guard.push_str(&msg);
                    guard.push_str(NEWLINE);
                }
            }
        }};
    }

    let system_hosts_path = get_hosts_file_path();
    let input_path = args.input.as_deref().unwrap_or(&system_hosts_path);
    let output_path = args.output.as_deref().unwrap_or(input_path);

    // Logging paths (useful for debug)
    if args.dry_run {
        log_msg!("DRY RUN MODE: No files will be modified.");
    }

    // Only log paths if they deviate from system default or debug is on,
    // but here we can just log them to confirm user choice.
    if args.debug {
        debug!("Input Path: {:?}", input_path);
        debug!("Output Path: {:?}", output_path);
    }

    log_msg!("Resolving final IP for: {} ...", source_domain);

    let ips = match resolve_ip(&source_domain).await {
        Ok(i) => i,
        Err(e) => {
            let err_msg = format!("Failed to resolve DNS ({}): {}", source_domain, e);
            if let Some(logger) = &gui_logger {
                if let Ok(mut guard) = logger.lock() {
                    guard.push_str(&err_msg);
                    guard.push_str(NEWLINE);
                }
            }
            return Err(eyre::eyre!(err_msg));
        }
    };

    if args.debug {
        debug!("Resolved IP list: {:?}", ips);
    }

    // Prefer IPv4 for compatibility
    let target_ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .ok_or_else(|| eyre::eyre!("No IP address found for {}", source_domain))?;

    log_msg!("Selected IP: {}", target_ip);

    // Call update logic
    match update_hosts_file(
        input_path,
        output_path,
        TARGET_DOMAIN,
        *target_ip,
        args.dry_run,
    )
    .await
    {
        Ok(logs) => {
            for line in logs {
                log_msg!("{}", line);
            }
            if args.dry_run {
                log_msg!("Simulation completed successfully.");
            } else {
                log_msg!("SUCCESS: Hosts file updated.");
            }
        }
        Err(e) => {
            // Check for permission errors specific to Windows/Unix
            let is_perm_error = e
                .downcast_ref::<std::io::Error>()
                .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false);

            if is_perm_error {
                log_msg!("ERROR: Permission Denied!");
                if cfg!(windows) {
                    log_msg!("Please run this application as Administrator.");
                } else {
                    log_msg!("Please run using sudo.");
                }
            } else {
                log_msg!("ERROR: {}", e);
            }
            return Err(e);
        }
    }

    Ok(())
}

#[instrument]
async fn resolve_ip(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((hostname, 0)).await?;
    Ok(addrs.map(|socket_addr| socket_addr.ip()).collect())
}

fn get_hosts_file_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use winapi::um::sysinfoapi::GetSystemDirectoryW;

        unsafe {
            const MAX_PATH: usize = 260;
            let mut buffer = [0u16; MAX_PATH];

            let len = GetSystemDirectoryW(buffer.as_mut_ptr(), MAX_PATH as u32) as usize;

            if len > 0 && len < MAX_PATH {
                let sys_dir = OsString::from_wide(&buffer[..len]);
                PathBuf::from(sys_dir)
                    .join("drivers")
                    .join("etc")
                    .join("hosts")
            } else {
                PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

async fn update_hosts_file(
    input_path: &Path,
    output_path: &Path,
    domain: &str,
    ip: IpAddr,
    dry_run: bool,
) -> Result<Vec<String>> {
    let mut logs = Vec::new();

    if !input_path.exists() {
        return Err(eyre::eyre!("Hosts file not found at {:?}", input_path));
    }

    let content = tokio::fs::read_to_string(input_path)
        .await
        .wrap_err_with(|| format!("Could not read file at {:?}", input_path))?;

    let mut new_content = String::with_capacity(content.len() + 128);
    let mut found_old = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            new_content.push_str(line);
            new_content.push_str(NEWLINE);
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let is_target_record = parts.len() >= 2 && parts[1..].contains(&domain);

        if is_target_record {
            found_old = true;
            debug!("Removing old record: {}", line);
            continue;
        }

        new_content.push_str(line);
        new_content.push_str(NEWLINE);
    }

    if !found_old {
        debug!(
            "No existing record found for {}, appending new one.",
            domain
        );
    }

    let new_record = format!("{} {}", ip, domain);
    logs.push(format!("Writing record: {}", new_record));

    new_content.push_str(&new_record);
    new_content.push_str(NEWLINE);

    if dry_run {
        logs.push(format!("Dry run: Skipping write to {:?}", output_path));
        return Ok(logs);
    }

    tokio::fs::write(output_path, new_content)
        .await
        .wrap_err_with(|| format!("Failed to write to {:?}", output_path))?;

    Ok(logs)
}

#[cfg(target_os = "windows")]
fn is_double_clicked() -> bool {
    unsafe {
        use winapi::um::wincon::GetConsoleProcessList;
        let mut process_list: [u32; 2] = [0; 2];
        let count = GetConsoleProcessList(process_list.as_mut_ptr(), 2);
        count == 1
    }
}

#[cfg(not(target_os = "windows"))]
fn is_double_clicked() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn run_gui_mode() -> Result<()> {
    unsafe {
        use winapi::um::wincon::GetConsoleWindow;
        use winapi::um::winuser::{SW_HIDE, ShowWindow};
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }

    enable_dpi_awareness();
    nwg::init().expect("Failed to init Native Windows GUI");
    let _app = HostsApp::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();
    Ok(())
}

#[cfg(target_os = "windows")]
fn enable_dpi_awareness() {
    unsafe {
        use winapi::shared::windef::DPI_AWARENESS_CONTEXT;
        use winapi::um::winuser::SetProcessDpiAwarenessContext;
        let dpi_aware_v2 = -4isize as DPI_AWARENESS_CONTEXT;
        let _ = SetProcessDpiAwarenessContext(dpi_aware_v2);
    }
}

#[cfg(target_os = "windows")]
#[derive(Default, NwgUi)]
pub struct HostsApp {
    #[nwg_control(size: (600, 550), position: (300, 300), title: "Microsoft Store Hosts Optimizer", flags: "WINDOW|VISIBLE|RESIZABLE")]
    #[nwg_events( OnWindowClose: [HostsApp::on_exit], OnInit: [HostsApp::init_ui] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 10)]
    layout: nwg::GridLayout,

    // Row 0
    #[nwg_control(text: "Target Domain:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 0)]
    label_domain: nwg::Label,

    #[nwg_control(text: TARGET_DOMAIN, readonly: true)]
    #[nwg_layout_item(layout: layout, col: 1, row: 0, col_span: 2)]
    input_domain: nwg::TextInput,

    // Row 1
    #[nwg_control(text: "DNS Source:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 1)]
    label_dns: nwg::Label,

    #[nwg_control(flags: "VISIBLE")]
    #[nwg_layout_item(layout: layout, col: 1, row: 1, col_span: 2)]
    combo_source: nwg::ComboBox<String>,

    // Row 2
    #[nwg_control(text: "Dry Run", check_state: nwg::CheckBoxState::Unchecked)]
    #[nwg_layout_item(layout: layout, col: 0, row: 2)]
    check_dry: nwg::CheckBox,

    #[nwg_control(text: "Auto Select", check_state: nwg::CheckBoxState::Checked)]
    #[nwg_layout_item(layout: layout, col: 1, row: 2)]
    #[nwg_events( OnButtonClick: [HostsApp::on_auto_check] )]
    check_auto: nwg::CheckBox,

    #[nwg_control(text: "Use Proxy", check_state: nwg::CheckBoxState::Unchecked)]
    #[nwg_layout_item(layout: layout, col: 2, row: 2)]
    check_proxy: nwg::CheckBox,

    // Row 3: Input File
    #[nwg_control(text: "Input File:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 3)]
    label_input: nwg::Label,

    #[nwg_control(text: "", readonly: false)]
    #[nwg_layout_item(layout: layout, col: 1, row: 3)]
    input_input_path: nwg::TextInput,

    #[nwg_control(text: "...", size: (10,22))]
    #[nwg_layout_item(layout: layout, col: 2, row: 3)]
    #[nwg_events( OnButtonClick: [HostsApp::on_browse_input] )]
    btn_browse_input: nwg::Button,

    // Row 4: Output File
    #[nwg_control(text: "Output File:", position: (0, 0))]
    #[nwg_layout_item(layout: layout, col: 0, row: 4)]
    label_output: nwg::Label,

    #[nwg_control(text: "", readonly: false)]
    #[nwg_layout_item(layout: layout, col: 1, row: 4)]
    input_output_path: nwg::TextInput,

    #[nwg_control(text: "...", size: (10,22))]
    #[nwg_layout_item(layout: layout, col: 2, row: 4)]
    #[nwg_events( OnButtonClick: [HostsApp::on_browse_output] )]
    btn_browse_output: nwg::Button,

    // Row 5
    #[nwg_control(text: "Update Hosts File", flags: "VISIBLE")]
    #[nwg_layout_item(layout: layout, col: 1, row: 5, col_span: 2)]
    #[nwg_events( OnButtonClick: [HostsApp::on_click_update] )]
    btn_update: nwg::Button,

    // Row 6+
    #[nwg_control(text: "Ready...", flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
    #[nwg_layout_item(layout: layout, col: 0, row: 6, col_span: 3, row_span: 5)]
    log_box: nwg::TextBox,

    #[nwg_control]
    #[nwg_events( OnNotice: [HostsApp::on_update_complete] )]
    notice: nwg::Notice,

    // File Dialogs
    #[nwg_resource(title: "Select Input Hosts File", action: nwg::FileDialogAction::Open, filters: "All (*.*)")]
    dialog_input: nwg::FileDialog,

    #[nwg_resource(title: "Select Output Hosts File", action: nwg::FileDialogAction::Save, filters: "All (*.*)")]
    dialog_output: nwg::FileDialog,

    logs: Arc<Mutex<String>>,
}

#[cfg(target_os = "windows")]
impl HostsApp {
    fn on_exit(&self) {
        nwg::stop_thread_dispatch();
    }

    fn init_ui(&self) {
        let names: Vec<String> = DNS_SOURCES.iter().map(|s| s.name.to_string()).collect();
        self.combo_source.set_collection(names);
        self.combo_source.set_selection(Some(0));
        self.on_auto_check(); // Set initial state

        // Initialize path fields with system default
        let default_path = get_hosts_file_path();
        if let Some(path_str) = default_path.to_str() {
            self.input_input_path.set_text(path_str);
            self.input_output_path.set_text(path_str);
        }
    }

    fn on_auto_check(&self) {
        // Toggle combo box enabled state based on auto check
        let is_auto = self.check_auto.check_state() == nwg::CheckBoxState::Checked;
        self.combo_source.set_enabled(!is_auto);
    }

    fn on_browse_input(&self) {
        if self.dialog_input.run(Some(&self.window)) {
            if let Ok(file_name) = self.dialog_input.get_selected_item() {
                self.input_input_path.set_text(&file_name.to_string_lossy());
            }
        }
    }

    fn on_browse_output(&self) {
        if self.dialog_output.run(Some(&self.window)) {
            if let Ok(file_name) = self.dialog_output.get_selected_item() {
                self.input_output_path
                    .set_text(&file_name.to_string_lossy());
            }
        }
    }

    fn on_click_update(&self) {
        self.btn_update.set_enabled(false);
        self.log_box.set_text("Initializing...\r\n");

        // UI Parameters
        let is_auto = self.check_auto.check_state() == nwg::CheckBoxState::Checked;
        let dry_run = self.check_dry.check_state() == nwg::CheckBoxState::Checked;
        let use_proxy = self.check_proxy.check_state() == nwg::CheckBoxState::Checked;
        let source_idx = self.combo_source.selection().unwrap_or(0);

        // Paths
        let in_txt = self.input_input_path.text();
        let out_txt = self.input_output_path.text();

        let input_opt = if in_txt.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(in_txt.trim()))
        };
        let output_opt = if out_txt.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(out_txt.trim()))
        };

        // Reset Logs
        if let Ok(mut logs) = self.logs.lock() {
            *logs = String::new();
        }

        let sender = self.notice.sender();
        let logs_handle = self.logs.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let args = Args {
                dry_run,
                debug: true,
                gui: true,
                input: input_opt,
                output: output_opt,
                source_index: source_idx,
                auto: is_auto,
                use_system_proxy: use_proxy,
            };

            let res = rt.block_on(async_main(args, Some(logs_handle.clone())));

            if let Err(e) = res {
                if let Ok(mut guard) = logs_handle.lock() {
                    guard.push_str(&format!("CRITICAL FAILURE: {:?}", e));
                }
            }
            sender.notice();
        });
    }

    fn on_update_complete(&self) {
        self.btn_update.set_enabled(true);
        if let Ok(content) = self.logs.lock() {
            self.log_box.set_text(&content);
        }
    }
}
