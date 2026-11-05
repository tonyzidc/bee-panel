use rand::Rng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

#[derive(Debug, Clone)]
pub struct GeneratedSshCredentials {
    pub private_key_pem: String,
    pub public_key_openssh: String,
    pub password_plain: String,
}

pub fn generate_credentials() -> anyhow::Result<GeneratedSshCredentials> {
    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("Failed to generate Ed25519 private key: {}", e))?;

    let private_key_pem = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("Failed to encode private key PEM: {}", e))?
        .to_string();

    let public_key_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("Failed to encode public key: {}", e))?;

    let password_plain = generate_secure_password(16);

    Ok(GeneratedSshCredentials {
        private_key_pem,
        public_key_openssh,
        password_plain,
    })
}

pub fn generate_secure_password(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn provision_linux_user(
    username: &str,
    credentials: &GeneratedSshCredentials,
    shell_mode: &str, // "sftp_only" | "standard_shell" | "sudo_admin"
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            tracing::warn!(
                "Not running as root. Skipping actual Linux user provisioning for '{}'",
                username
            );
            return Ok(());
        }

        let shell = "/bin/bash";

        // Check if user already exists
        let user_exists = Command::new("id")
            .arg("-u")
            .arg(username)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !user_exists {
            let mut cmd = Command::new("useradd");
            cmd.args(&["-m", "-s", shell, username]);
            let status = cmd.status()?;
            if !status.success() {
                return Err(anyhow::anyhow!("useradd failed for user {}", username));
            }
        } else {
            // Update shell if user exists
            let status = Command::new("usermod")
                .args(&["-s", shell, username])
                .status()?;
            if !status.success() {
                anyhow::bail!("usermod failed for {}", username);
            }
        }

        // Add to sudo/wheel if sudo_admin
        if shell_mode == "sudo_admin" {
            let group = if Command::new("getent")
                .args(&["group", "sudo"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                "sudo"
            } else {
                "wheel"
            };
            let status = Command::new("usermod")
                .args(&["-aG", group, username])
                .status()?;
            if !status.success() {
                anyhow::bail!("Could not grant sudo group to {}", username);
            }
        }

        // Set Linux user password via chpasswd
        let mut chpasswd = Command::new("chpasswd")
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = chpasswd.stdin.take() {
            use std::io::Write;
            write!(stdin, "{}:{}\n", username, credentials.password_plain)?;
        }
        if !chpasswd.wait()?.success() {
            anyhow::bail!("chpasswd failed for {}", username);
        }

        // Setup ~/.ssh/authorized_keys
        let home_dir = PathBuf::from(format!("/home/{}", username));
        if home_dir.exists() {
            let ssh_dir = home_dir.join(".ssh");
            fs::create_dir_all(&ssh_dir)?;

            let auth_keys = ssh_dir.join("authorized_keys");
            fs::write(&auth_keys, format!("{}\n", credentials.public_key_openssh))?;

            // Set file permissions
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&auth_keys, fs::Permissions::from_mode(0o600))?;

            // chown -R username:username ~/.ssh
            let status = Command::new("chown")
                .args(&[
                    "-R",
                    &format!("{}:{}", username, username),
                    ssh_dir.to_str().unwrap(),
                ])
                .status()?;
            if !status.success() {
                anyhow::bail!("Could not set SSH key owner for {}", username);
            }

            // Setup web directory /var/www/vhosts/<username>
            let web_dir = PathBuf::from(format!("/var/www/vhosts/{}", username));
            if !web_dir.exists() {
                fs::create_dir_all(&web_dir)?;
                let status = Command::new("chown")
                    .args(&[
                        "-R",
                        &format!("{}:{}", username, username),
                        web_dir.to_str().unwrap(),
                    ])
                    .status()?;
                if !status.success() {
                    anyhow::bail!("Could not set web directory owner for {}", username);
                }
            }
        }

        configure_sftp_only(username, shell_mode == "sftp_only")?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = credentials;
        tracing::info!(
            "Running on non-Linux OS. Mocked OS user provisioning for '{}' ({})",
            username,
            shell_mode
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_sftp_only(username: &str, enabled: bool) -> anyhow::Result<()> {
    let directory = Path::new("/etc/ssh/sshd_config.d");
    if !directory.exists() {
        return Ok(());
    }
    let path = directory.join(format!("90-bee-panel-{}.conf", username));
    let old = fs::read(&path).ok();
    if enabled {
        fs::write(&path, format!(
            "Match User {}\n    ForceCommand internal-sftp\n    AllowTcpForwarding no\n    X11Forwarding no\n    PermitTTY no\n", username
        ))?;
    } else if path.exists() {
        fs::remove_file(&path)?;
    }
    let test = Command::new("sshd").arg("-t").status()?;
    if !test.success() {
        if let Some(content) = old {
            fs::write(&path, content)?;
        } else {
            let _ = fs::remove_file(&path);
        }
        anyhow::bail!("sshd configuration test failed");
    }
    let reload = Command::new("systemctl").args(["reload", "ssh"]).status()?;
    if !reload.success() {
        anyhow::bail!("Could not reload SSH service");
    }
    Ok(())
}

pub fn delete_linux_user(username: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } == 0 {
            let exists = Command::new("id")
                .arg("-u")
                .arg(username)
                .status()?
                .success();
            if exists && !Command::new("userdel").arg(username).status()?.success() {
                anyhow::bail!("userdel failed for {}", username);
            }
            configure_sftp_only(username, false)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = username;
    Ok(())
}

pub fn set_linux_user_password(username: &str, password: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } == 0
            && Command::new("id")
                .arg("-u")
                .arg(username)
                .output()?
                .status
                .success()
        {
            let mut child = Command::new("chpasswd")
                .stdin(std::process::Stdio::piped())
                .spawn()?;
            use std::io::Write;
            write!(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("chpasswd stdin unavailable"))?,
                "{}:{}\n",
                username,
                password
            )?;
            if !child.wait()?.success() {
                anyhow::bail!("chpasswd failed for {}", username);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (username, password);
    Ok(())
}

#[allow(dead_code)]
pub fn rotate_ssh_key(username: &str) -> anyhow::Result<GeneratedSshCredentials> {
    let creds = generate_credentials()?;
    provision_linux_user(username, &creds, "standard_shell")?;
    Ok(creds)
}
