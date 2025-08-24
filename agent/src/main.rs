// agent/src/main.rs
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod command_poller;
mod network_client;
mod secure_mount;
mod sync;
mod usb_monitor;

use common::{AgentConfig, DeviceInfo, FileInfo, FileManifest};

pub struct RustyAgent {
    config: AgentConfig,
}

impl RustyAgent {
    pub fn new() -> Result<Self> {
        let mut config = AgentConfig::load()?;

        if config.agent_id.is_empty() {
            config.agent_id = Self::generate_agent_id()?;
            Self::save_agent_id(&config.agent_id)?;
        }

        Ok(Self { config })
    }

    fn generate_agent_id() -> Result<String> {
        let machine_id = machine_uid::get().unwrap_or_else(|_| "unknown".to_string());
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", machine_id, timestamp));
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn save_agent_id(agent_id: &str) -> Result<()> {
        let config_path = "/etc/rustykey/config/agent.conf";
        let mut content = fs::read_to_string(config_path).unwrap_or_default();

        if content.contains("RUSTYKEY_AGENT_ID=") {
            content = content
                .lines()
                .map(|line| {
                    if line.starts_with("RUSTYKEY_AGENT_ID=") {
                        format!("RUSTYKEY_AGENT_ID={}", agent_id)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
        } else {
            content.push_str(&format!("\nRUSTYKEY_AGENT_ID={}\n", agent_id));
        }

        fs::write(config_path, content)?;
        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        secure_mount::init_mount_namespace()?;
        fs::create_dir_all(&self.config.mount_path)?;

        self.register_with_backend().await?;
        self.check_existing_mounts()?;
        self.monitor_usb_devices().await
    }

    async fn register_with_backend(&self) -> Result<()> {
        let mut client = network_client::SecureClient::connect(
            &self.config.backend_addr,
            self.config.agent_id.clone(),
        )
        .await?;

        let hostname = get_hostname();
        match client.register_with_description(Some(hostname)).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("⚠ Registration failed: {} (continuing anyway)", e);
            }
        }

        Ok(())
    }

    fn check_existing_mounts(&self) -> Result<()> {
        if let Ok(mounts) = secure_mount::list_active_mounts() {
            if !mounts.is_empty() {
                eprintln!("⚠ Found {} existing RustyKey mounts", mounts.len());
            }
        }
        Ok(())
    }

    async fn monitor_usb_devices(&self) -> Result<()> {
        let mut monitor = usb_monitor::UsbMonitor::new()?;
        let mounted_devices = Arc::new(tokio::sync::Mutex::new(
            HashMap::<String, MountedDevice>::new(),
        ));

        loop {
            if let Some(event) = monitor.wait_for_event().await? {
                match event {
                    usb_monitor::UsbEvent::Connected(device_path, serial) => {
                        self.handle_device_connected(device_path, serial, mounted_devices.clone())
                            .await;
                    }
                    usb_monitor::UsbEvent::Disconnected(serial) => {
                        self.handle_device_disconnected(serial, mounted_devices.clone())
                            .await;
                    }
                }
            }
        }
    }

    async fn handle_device_connected(
        &self,
        device_path: PathBuf,
        serial: String,
        mounted_devices: Arc<tokio::sync::Mutex<HashMap<String, MountedDevice>>>,
    ) {
        let device_str = device_path.to_string_lossy();
        if !device_str.ends_with(|c: char| c.is_numeric()) {
            return;
        }

        let agent_id = self.config.agent_id.clone();
        let backend_addr = self.config.backend_addr.clone();
        let serial_clone = serial.clone();

        tokio::spawn(async move {
            match process_usb_device(
                device_path,
                agent_id.clone(),
                backend_addr.clone(),
                serial_clone.clone(),
            )
            .await
            {
                Ok((mount_point, bucket_id)) => {
                    let services =
                        start_device_services(&mount_point, bucket_id, backend_addr, agent_id)
                            .await;

                    mounted_devices.lock().await.insert(
                        serial_clone,
                        MountedDevice {
                            mount_point,
                            services,
                        },
                    );
                }
                Err(e) => eprintln!("❌ Failed to process device: {}", e),
            }
        });
    }

    async fn handle_device_disconnected(
        &self,
        serial: String,
        mounted_devices: Arc<tokio::sync::Mutex<HashMap<String, MountedDevice>>>,
    ) {
        if let Some(device) = mounted_devices.lock().await.remove(&serial) {
            if let Some(services) = device.services {
                services.sync_handle.abort();
                services.command_handle.abort();
            }

            tokio::spawn(async move {
                if let Err(e) = secure_mount::unmount_isolated(&device.mount_point) {
                    eprintln!("Failed to unmount: {}", e);
                }
            });
        }

        let agent_id = self.config.agent_id.clone();
        let backend_addr = self.config.backend_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = notify_disconnection(&backend_addr, &agent_id, &serial).await {
                eprintln!("Failed to notify backend: {}", e);
            }
        });
    }
}

struct MountedDevice {
    mount_point: PathBuf,
    services: Option<DeviceServices>,
}

struct DeviceServices {
    sync_handle: tokio::task::JoinHandle<()>,
    command_handle: tokio::task::JoinHandle<()>,
}

async fn process_usb_device(
    device_path: PathBuf,
    agent_id: String,
    backend_addr: String,
    serial: String,
) -> Result<(PathBuf, Uuid)> {
    let mut device_info = get_device_info(&device_path)?;
    device_info.serial = serial.clone();

    let mount_point = secure_mount::mount_isolated(&device_path)?;

    let bucket_id =
        match authenticate_and_scan(&mount_point, &agent_id, &backend_addr, device_info).await {
            Ok(id) => id,
            Err(e) => {
                let _ = secure_mount::unmount_isolated(&mount_point);
                return Err(e);
            }
        };

    Ok((mount_point, bucket_id))
}

async fn authenticate_and_scan(
    mount_point: &Path,
    agent_id: &str,
    backend_addr: &str,
    device_info: DeviceInfo,
) -> Result<Uuid> {
    let mut client =
        network_client::SecureClient::connect(backend_addr, agent_id.to_string()).await?;

    let (session_id, bucket_id, banned_extensions) = client.authenticate(device_info).await?;

    let manifest = scan_device(mount_point, session_id, agent_id, &banned_extensions)?;

    client.send_manifest(manifest).await?;
    Ok(bucket_id)
}

async fn start_device_services(
    mount_point: &Path,
    bucket_id: Uuid,
    backend_addr: String,
    agent_id: String,
) -> Option<DeviceServices> {
    let sync_service = sync::SyncService::new(
        mount_point,
        bucket_id,
        backend_addr.clone(),
        agent_id.clone(),
    );

    let sync_handle = tokio::spawn(async move {
        if let Err(e) = sync_service.run().await {
            eprintln!("Sync service error: {}", e);
        }
    });

    let command_poller =
        match command_poller::CommandPoller::new(mount_point, bucket_id, backend_addr, agent_id) {
            Ok(poller) => poller,
            Err(e) => {
                eprintln!("Failed to create command poller: {}", e);
                return None;
            }
        };

    let command_handle = tokio::spawn(async move {
        if let Err(e) = command_poller.run().await {
            eprintln!("Command poller error: {}", e);
        }
    });

    Some(DeviceServices {
        sync_handle,
        command_handle,
    })
}

async fn notify_disconnection(backend_addr: &str, agent_id: &str, serial: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let payload = serde_json::json!({
        "agent_id": agent_id,
        "serial": serial,
    });

    client
        .post(format!("https://{}/agent/disconnect", backend_addr))
        .json(&payload)
        .send()
        .await?;

    Ok(())
}

fn get_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn get_device_info(device_path: &Path) -> Result<DeviceInfo> {
    let output = Command::new("udevadm")
        .args(&["info", "--query=all", "--name"])
        .arg(device_path)
        .output()?;

    let info = String::from_utf8_lossy(&output.stdout);

    Ok(DeviceInfo {
        vendor_id: 0x1234,
        product_id: 0x5678,
        serial: extract_serial(&info).unwrap_or_default(),
        capacity: get_device_capacity(device_path)?,
    })
}

fn extract_serial(udev_info: &str) -> Option<String> {
    udev_info
        .lines()
        .find(|line| line.contains("ID_SERIAL_SHORT="))
        .and_then(|line| line.split('=').nth(1))
        .map(|s| s.to_string())
}

fn get_device_capacity(device_path: &Path) -> Result<u64> {
    let size_path = format!(
        "/sys/block/{}/size",
        device_path.file_name().unwrap().to_string_lossy()
    );

    let size_str = fs::read_to_string(&size_path).unwrap_or_else(|_| "0".to_string());
    let sectors: u64 = size_str.trim().parse().unwrap_or(0);
    Ok(sectors * 512)
}

fn scan_device(
    mount_point: &Path,
    session_id: Uuid,
    agent_id: &str,
    banned_extensions: &[String],
) -> Result<FileManifest> {
    let mut files = Vec::new();
    let mut filtered_count = 0;

    scan_directory(
        mount_point,
        mount_point,
        &mut files,
        banned_extensions,
        &mut filtered_count,
    )?;

    Ok(FileManifest {
        device_id: mount_point.to_string_lossy().to_string(),
        files,
        session_id,
        agent_id: agent_id.to_string(),
    })
}

fn scan_directory(
    dir: &Path,
    base: &Path,
    files: &mut Vec<FileInfo>,
    banned_extensions: &[String],
    filtered_count: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Ok(metadata) = fs::metadata(&path) {
            if metadata.is_file() {
                let relative_path = path.strip_prefix(base)?;
                let path_str = relative_path.to_string_lossy().to_string();

                if should_filter(&path_str, banned_extensions) {
                    *filtered_count += 1;
                    continue;
                }

                files.push(FileInfo {
                    path: path_str,
                    size: metadata.len(),
                    hash: hash_file(&path)?,
                    modified: metadata.modified()?.duration_since(UNIX_EPOCH)?.as_secs(),
                });
            } else if metadata.is_dir() && !is_system_directory(&path) {
                scan_directory(&path, base, files, banned_extensions, filtered_count)?;
            }
        }
    }
    Ok(())
}

fn should_filter(path: &str, banned_extensions: &[String]) -> bool {
    let path_lower = path.to_lowercase();
    banned_extensions.iter().any(|ext| path_lower.contains(ext))
}

fn is_system_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                "System Volume Information"
                    | "$RECYCLE.BIN"
                    | ".Trash-1000"
                    | "lost+found"
                    | ".rustykey_mount"
            )
        })
        .unwrap_or(false)
}

fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    if !nix::unistd::Uid::current().is_root() {
        eprintln!("❌ RustyKey agent must run as root");
        std::process::exit(1);
    }

    if let Ok(config) = AgentConfig::load() {
        unsafe {
            std::env::set_var("RUST_LOG", &config.log_level);
        }
    }
    env_logger::init();

    let agent = RustyAgent::new()?;
    agent.run().await
}
