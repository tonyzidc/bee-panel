use crate::config::AppConfig;
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub struct AcmeManager {
    config: AppConfig,
}

pub struct IssuedCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_at: String,
}

impl AcmeManager {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub async fn issue_letsencrypt_cert(
        &self,
        domain_names: &[String],
        contact_email: &str,
        is_staging: bool,
    ) -> anyhow::Result<IssuedCertificate> {
        if domain_names.is_empty() {
            return Err(anyhow::anyhow!("At least one domain name is required"));
        }

        let dir_url = if is_staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        tracing::info!(
            "Starting ACME issuance for domains: {:?} with contact: {}",
            domain_names,
            contact_email
        );

        // 1. Create ACME Account
        let (account, _) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", contact_email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir_url,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ACME account: {}", e))?;

        // 2. Create Order
        let identifiers: Vec<Identifier> = domain_names
            .iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create ACME order: {}", e))?;

        // 3. Process Authorizations & HTTP-01 Challenges
        let mut authorizations = order.authorizations().await?;
        for auth in authorizations.iter_mut() {
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("HTTP-01 challenge not offered by ACME provider"))?;

            let key_auth = order.key_authorization(challenge);

            // Write key authorization file to /var/lib/bee-panel/acme-challenges/<token>
            let challenge_path = self.config.acme_challenge_dir.join(&challenge.token);
            fs::create_dir_all(&self.config.acme_challenge_dir)?;
            fs::write(&challenge_path, key_auth.as_str())?;

            tracing::info!(
                "Wrote ACME HTTP-01 challenge to {:?}",
                challenge_path
            );

            // Notify ACME provider that challenge is ready
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to mark challenge ready: {}", e))?;
        }

        // 4. Poll Order until Valid
        let mut attempts = 0;
        let max_attempts = 30;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            order.refresh().await?;

            match order.state().status {
                OrderStatus::Ready => {
                    tracing::info!("ACME Order is ready for finalization");
                    break;
                }
                OrderStatus::Valid => {
                    tracing::info!("ACME Order is valid");
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(anyhow::anyhow!("ACME Order verification failed / invalid"));
                }
                _ => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(anyhow::anyhow!("ACME challenge verification timed out"));
                    }
                }
            }
        }

        // 5. Generate Private Key and CSR
        let key_pair = KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("Failed to generate certificate key pair: {}", e))?;
        let key_pem = key_pair.serialize_pem();

        let mut params = CertificateParams::new(domain_names.to_vec())
            .map_err(|e| anyhow::anyhow!("Failed to create certificate params: {}", e))?;
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, &domain_names[0]);
        params.distinguished_name = dn;

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| anyhow::anyhow!("Failed to generate CSR: {}", e))?;

        // 6. Finalize Order with CSR DER
        order
            .finalize(csr.der())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to finalize ACME order: {}", e))?;

        // 7. Download Certificate
        let cert_chain_pem = loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            order.refresh().await?;
            if let Some(cert) = order.certificate().await? {
                break cert;
            }
        };

        // Calculate expires_at (typically 90 days for Let's Encrypt)
        let expires_at = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();

        // Cleanup challenges
        let _ = fs::remove_dir_all(&self.config.acme_challenge_dir);
        let _ = fs::create_dir_all(&self.config.acme_challenge_dir);

        Ok(IssuedCertificate {
            cert_pem: cert_chain_pem,
            key_pem,
            expires_at,
        })
    }

    pub fn save_certificate(
        &self,
        cert_id: i64,
        cert_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let dir = self.config.certs_dir.join(format!("{}", cert_id));
        fs::create_dir_all(&dir)?;

        let cert_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");

        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

        // Set secure permissions on private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }

        Ok((cert_path, key_path))
    }
}
