// agent/src/usb_monitor.rs
use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::mpsc;
use udev::{Device, MonitorBuilder};

#[derive(Debug, Clone)]
pub enum UsbEvent {
    Connected(PathBuf, String),
    Disconnected(String),
}

pub struct UsbMonitor {
    receiver: mpsc::Receiver<UsbEvent>,
}

impl UsbMonitor {
    pub fn new() -> Result<Self> {
        let (tx, rx) = mpsc::channel(10);
        std::thread::spawn(move || {
            if let Err(e) = monitor_usb_devices(tx) {
                eprintln!("USB monitor error: {e}");
            }
        });
        Ok(Self { receiver: rx })
    }

    pub async fn wait_for_event(&mut self) -> Result<Option<UsbEvent>> {
        Ok(self.receiver.recv().await)
    }
}

fn monitor_usb_devices(tx: mpsc::Sender<UsbEvent>) -> Result<()> {
    let monitor = MonitorBuilder::new()?.match_subsystem("block")?.listen()?;

    loop {
        let event = monitor.iter().next();
        if let Some(event) = event {
            let device = event.device();
            match event.event_type() {
                udev::EventType::Add => {
                    if is_usb_storage(&device) || is_usb_partition(&device) {
                        if let Some(devnode) = device.devnode() {
                            let serial = get_device_serial(&device)
                                .unwrap_or_else(|| format!("unknown-{}", uuid::Uuid::new_v4()));
                            let _ = tx
                                .blocking_send(UsbEvent::Connected(devnode.to_path_buf(), serial));
                        }
                    }
                }
                udev::EventType::Remove => {
                    if is_usb_storage(&device) || is_usb_partition(&device) {
                        let serial = get_device_serial(&device).unwrap_or_default();
                        if !serial.is_empty() {
                            let _ = tx.blocking_send(UsbEvent::Disconnected(serial));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn get_device_serial(device: &Device) -> Option<String> {
    device
        .property_value("ID_SERIAL_SHORT")
        .or_else(|| device.property_value("ID_SERIAL"))
        .map(|s| s.to_string_lossy().to_string())
}

fn is_usb_storage(device: &Device) -> bool {
    device
        .property_value("ID_BUS")
        .map(|v| v == "usb")
        .unwrap_or(false)
        && device
            .property_value("DEVTYPE")
            .map(|v| v == "disk")
            .unwrap_or(false)
}

fn is_usb_partition(device: &Device) -> bool {
    device
        .property_value("ID_BUS")
        .map(|v| v == "usb")
        .unwrap_or(false)
        && device
            .property_value("DEVTYPE")
            .map(|v| v == "partition")
            .unwrap_or(false)
}
