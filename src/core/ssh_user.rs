use rand::Rng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

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

fn generate_secure_password(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
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
    _credentials: &GeneratedSshCredentials,
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

        // Determine login shell based on shell_mode
        let shell = match shell_mode {
            "sftp_only" => {
                if Path::new("/usr/lib/openssh/sftp-server").exists() {
                    "/usr/lib/openssh/sftp-server"
                } else if Path::new("/usr/libexec/openssh/sftp-server").exists() {
                    "/usr/libexec/openssh/sftp-server"
                } else {
                    "/sbin/nologin"
                }
            }
            "sudo_admin" | "standard_shell" | _ => "/bin/bash",
        };

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
            let _ = Command::new("usermod")
                .args(&["-s", shell, username])
                .status();
        }

        // Add to sudo/wheel if sudo_admin
        if shell_mode == "sudo_admin" {
            let group = if Command::new("getent").args(&["group", "sudo"]).output().map(|o| o.status.success()).unwrap_or(false) {
                "sudo"
            } else {
                "wheel"
            };
            let _ = Command::new("usermod")
                .args(&["-aG", group, username])
                .status();
        }

        // Set Linux user password via chpasswd
        let mut chpasswd = Command::new("chpasswd")
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = chpasswd.stdin.take() {
            use std::io::Write;
            write!(stdin, "{}:{}\n", username, credentials.password_plain)?;
        }
        let _ = chpasswd.wait();

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
            let _ = Command::new("chown")
                .args(&["-R", &format!("{}:{}", username, username), ssh_dir.to_str().unwrap()])
                .status();

            // Setup web directory /var/www/vhosts/<username>
            let web_dir = PathBuf::from(format!("/var/www/vhosts/{}", username));
            if !web_dir.exists() {
                let _ = fs::create_dir_all(&web_dir);
                let _ = Command::new("chown")
                    .args(&["-R", &format!("{}:{}", username, username), web_dir.to_str().unwrap()])
                    .status();
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::info!(
            "Running on non-Linux OS. Mocked OS user provisioning for '{}' ({})",
            username,
            shell_mode
        );
    }

    Ok(())
}

#[allow(dead_code)]
pub fn rotate_ssh_key(username: &str) -> anyhow::Result<GeneratedSshCredentials> {
    let creds = generate_credentials()?;
    provision_linux_user(username, &creds, "standard_shell")?;
    Ok(creds)
}
