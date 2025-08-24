// agent/src/secure_mount.rs
use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Gid, Uid, chown};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Once;

static NAMESPACE_INIT: Once = Once::new();

pub fn init_mount_namespace() -> Result<()> {
    let mut result = Ok(());
    NAMESPACE_INIT.call_once(|| {
        if let Err(e) = setup_mount_namespace() {
            result = Err(e);
        }
    });
    result
}

fn setup_mount_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("Failed to create mount namespace")?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("Failed to make mount namespace private")?;

    let isolated_base = "/var/lib/rustykey/mounts";
    fs::create_dir_all(isolated_base).context("Failed to create isolated mount base directory")?;
    let mut perms = fs::metadata(isolated_base)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(isolated_base, perms)?;
    chown(
        isolated_base,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )?;
    Ok(())
}

pub fn mount_isolated(device_path: &Path) -> Result<PathBuf> {
    mount_isolated_with_base(device_path, "/var/lib/rustykey/mounts")
}

pub fn mount_isolated_with_base(device_path: &Path, base_path: &str) -> Result<PathBuf> {
    init_mount_namespace()?;
    let mount_id = uuid::Uuid::new_v4();
    let isolated_mount = PathBuf::from(format!("{base_path}/usb_{mount_id}"));

    if !Uid::current().is_root() {
        return Err(anyhow::anyhow!("Must be root to mount devices securely"));
    }

    fs::create_dir_all(&isolated_mount)
        .with_context(|| format!("Failed to create mount point: {isolated_mount:?}"))?;
    let mut perms = fs::metadata(&isolated_mount)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&isolated_mount, perms)?;
    chown(
        &isolated_mount,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )?;

    let fs_type = detect_filesystem(device_path)?;

    let mount_flags = MsFlags::MS_NOEXEC
        | MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV
        | MsFlags::MS_NOATIME
        | MsFlags::MS_RELATIME;

    let mount_options = match fs_type.as_str() {
        "ntfs-3g" | "ntfs3" => Some("uid=0,gid=0,umask=077,norecover"),
        "vfat" | "fat32" => Some("uid=0,gid=0,umask=077,quiet"),
        "exfat" => Some("uid=0,gid=0,umask=077"),
        _ => None,
    };

    mount(
        Some(device_path),
        &isolated_mount,
        Some(fs_type.as_str()),
        mount_flags,
        mount_options,
    )
    .with_context(|| {
        format!(
            "Failed to mount device {:?} to {:?}",
            device_path, isolated_mount
        )
    })?;

    let access_point = create_bind_mount_access(&isolated_mount, &mount_id)?;

    let marker_path = isolated_mount.join(".rustykey_mount");
    let metadata = serde_json::json!({
        "mount_id": mount_id.to_string(),
        "device": device_path.to_string_lossy(),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "namespace": "isolated",
        "access_point": access_point.to_string_lossy(),
    });
    fs::write(&marker_path, metadata.to_string()).ok();

    Ok(access_point)
}

fn create_bind_mount_access(isolated_mount: &Path, mount_id: &uuid::Uuid) -> Result<PathBuf> {
    let access_base = "/tmp/rustykey";
    fs::create_dir_all(access_base)?;
    let access_point = PathBuf::from(format!("{access_base}/{mount_id}"));
    fs::create_dir_all(&access_point)?;
    let mut perms = fs::metadata(&access_point)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&access_point, perms)?;

    mount(
        Some(isolated_mount),
        &access_point,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "Failed to create bind mount from {:?} to {:?}",
            isolated_mount, access_point
        )
    })?;

    mount(
        None::<&str>,
        &access_point,
        None::<&str>,
        MsFlags::MS_REMOUNT
            | MsFlags::MS_BIND
            | MsFlags::MS_NOEXEC
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .context("Failed to remount bind mount with security flags")?;

    Ok(access_point)
}

pub fn unmount_isolated(mount_point: &Path) -> Result<()> {
    if !Uid::current().is_root() {
        return Err(anyhow::anyhow!("Must be root to unmount devices"));
    }

    let mount_id = mount_point
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());

    umount2(mount_point, MntFlags::MNT_DETACH)
        .with_context(|| format!("Failed to unmount access point {mount_point:?}"))?;
    fs::remove_dir(mount_point)
        .with_context(|| format!("Failed to remove access point {mount_point:?}"))?;

    if let Some(id) = mount_id {
        let isolated_mount = PathBuf::from(format!("/var/lib/rustykey/mounts/usb_{id}"));
        if isolated_mount.exists() {
            let marker_path = isolated_mount.join(".rustykey_mount");
            let _ = fs::remove_file(&marker_path);

            umount2(&isolated_mount, MntFlags::MNT_DETACH)
                .with_context(|| format!("Failed to unmount isolated mount {isolated_mount:?}"))?;

            fs::remove_dir(&isolated_mount)
                .with_context(|| format!("Failed to remove isolated mount {isolated_mount:?}"))?;
        }
    }

    Ok(())
}

fn detect_filesystem(device_path: &Path) -> Result<String> {
    use std::process::Command;

    let output = Command::new("blkid")
        .arg("-s")
        .arg("TYPE")
        .arg("-o")
        .arg("value")
        .arg(device_path)
        .output()
        .context("Failed to run blkid")?;

    if output.status.success() {
        let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !fs_type.is_empty() {
            return Ok(match fs_type.as_str() {
                "ntfs" => "ntfs-3g".to_string(),
                other => other.to_string(),
            });
        }
    }

    let output = Command::new("file")
        .arg("-s")
        .arg(device_path)
        .output()
        .context("Failed to run file command")?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    if output_str.contains("FAT") || output_str.contains("DOS") {
        Ok("vfat".to_string())
    } else if output_str.contains("NTFS") {
        Ok("ntfs-3g".to_string())
    } else if output_str.contains("ext4") {
        Ok("ext4".to_string())
    } else if output_str.contains("ext3") {
        Ok("ext3".to_string())
    } else if output_str.contains("ext2") {
        Ok("ext2".to_string())
    } else if output_str.contains("exFAT") {
        Ok("exfat".to_string())
    } else {
        Ok("auto".to_string())
    }
}

pub fn is_rustykey_mount(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    let access_marker = path.join(".rustykey_mount");
    if access_marker.exists() {
        return true;
    }

    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let path_str = path.to_string_lossy();
        return mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == path_str && line.contains("/var/lib/rustykey/mounts")
        });
    }
    false
}

pub fn list_active_mounts() -> Result<Vec<PathBuf>> {
    let mut mounts = Vec::new();
    let access_base = Path::new("/tmp/rustykey");
    if access_base.exists() {
        for entry in fs::read_dir(access_base)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && is_rustykey_mount(&path) {
                mounts.push(path);
            }
        }
    }
    Ok(mounts)
}
