use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::buf::BufExt as _;
use hyper::{body, client::HttpConnector, Body, Client, Method, Request};
use hyper_openssl::HttpsConnector;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use std::{env, fs};

/// The name of the standard Vault token header.
const TOKEN_HEADER: &str = "X-Vault-Token";

type VaultClient = Client<HttpsConnector<HttpConnector>>;

pub struct Vault {
    /// The address of the Vault server.
    addr: String,
    /// The mounted path to use for signing. This can be a Vault transit backend
    /// path or a Vault GPG plugin path. You can also optionally specify the
    /// hashing algorithm as a parameter.
    ///
    /// Examples:
    /// - transit/sign/name(/:algorithm)
    /// - gpg/sign/name(/:algorithm)
    sig_path: String,
    /// The mounted path to use for verifying. This can be a Vault transit
    /// backend path or a Vault GPG plugin path.
    ///
    /// Examples:
    /// - transit/verify/name
    /// - gpg/verify/name
    ver_path: String,
    /// The currently initialised Vault client.
    client: VaultClient,
}

#[derive(Deserialize)]
pub struct VaultResponse<D> {
    /// We only care about the data field in Vault responses.
    pub data: Option<D>,
}

#[async_trait]
pub trait SignatureOps {
    /// Remotely sign the data using the configured Vault `sig_path` and return
    /// a detached signature string.
    async fn sign<D>(&self, data: D) -> Result<String>
    where
        D: Send + Sync + Default + AsRef<[u8]>;
    /// Remotely verify original data and detached signature using the
    /// configured Vault `ver_path`.
    async fn verify<D, S>(&self, data: D, sig: S) -> Result<()>
    where
        D: Send + Sync + AsRef<[u8]>,
        S: Send + Sync + Into<String>;
}

impl Vault {
    /// Creates a new Vault client with sign and verify capabilities.
    pub fn new<S>(addr: S, sig_path: S, ver_path: S) -> Result<Self>
    where
        S: Into<String>,
    {
        // Build the client.
        let mut conn = HttpsConnector::new()?;
        if let Ok(tls_server_name) = env::var("VAULT_TLS_SERVER_NAME") {
            conn.set_callback(move |c, _| {
                // Prevent native TLS lib from inferring and verifying a SNI.
                c.set_use_server_name_indication(false);
                c.set_verify_hostname(false);

                // And set the user provided SNI.
                c.set_hostname(&tls_server_name)
            });
        };

        Ok(Vault {
            client: Client::builder().build::<_, Body>(conn),
            addr: addr.into(),
            sig_path: sig_path.into(),
            ver_path: ver_path.into(),
        })
    }

    async fn put_endpoint<D>(&self, endpoint: &str, req: String) -> Result<VaultResponse<D>>
    where
        D: DeserializeOwned,
    {
        let res = self
            .client
            .request(
                Request::builder()
                    .method(Method::PUT)
                    .header(
                        TOKEN_HEADER,
                        self.token()
                            .context(anyhow!("vault: failed to construct request header"))?,
                    )
                    .uri(format!("{}/v1/{}", self.addr, endpoint))
                    .body(Body::from(req))
                    .context(anyhow!("vault: failed to construct request body"))?,
            )
            .await?;

        if res.status().is_success() {
            Ok(serde_json::from_reader(
                body::aggregate(res)
                    .await
                    .context(anyhow!("vault: failed to aggregate response body"))?
                    .reader(),
            )
            .context(anyhow!("vault: failed to parse response body"))?)
        } else {
            Err(anyhow!(
                "vault: request unsuccessful {} - {}",
                res.status().as_str(),
                res.status().canonical_reason().unwrap_or("<none>"),
            ))
        }
    }

    /// Discovers the existing Vault token from either the environment or the
    /// home directory using HashiCorp's established naming and paths. The
    /// environment takes precedence.
    pub fn token(&self) -> Result<String> {
        env::var("VAULT_TOKEN").or_else(|_| {
            let mut path = dirs::home_dir().ok_or(anyhow!("vault: cannot find homedir"))?;
            path.push(".vault-token");
            Ok(fs::read_to_string(path)?)
        })
    }
}

#[derive(Serialize)]
struct SignRequest<D: AsRef<[u8]>> {
    /// The input data to sign. As per the Vault interface specification, the
    /// input data will be serialised as base64.
    #[serde(serialize_with = "as_base64")]
    input: D,
    /// The encoding format for the returned signature. Only applies to the
    /// Vault GPG plugin. Options are "base64" or "ascii-armor".
    format: String,
}

impl<D> Default for SignRequest<D>
where
    D: Default + AsRef<[u8]>,
{
    fn default() -> SignRequest<D> {
        SignRequest {
            input: D::default(),
            // Default to "ascii-armor".
            format: String::from("ascii-armor"),
        }
    }
}

#[derive(Deserialize)]
struct SignResponse {
    /// The signature created for the provided data.
    signature: String,
}

#[derive(Serialize)]
struct VerifyRequest<D: AsRef<[u8]>> {
    /// The input data to verify. As per the Vault interface specification, the
    /// input data will be serialised as base64.
    #[serde(serialize_with = "as_base64")]
    input: D,
    /// The signature to verify.
    signature: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    /// Indicates whether the provided signature was valid or not.
    valid: bool,
}

#[async_trait]
impl SignatureOps for Vault {
    async fn sign<D>(&self, data: D) -> Result<String>
    where
        D: Send + Sync + Default + AsRef<[u8]>,
    {
        self.put_endpoint::<SignResponse>(
            &self.sig_path,
            serde_json::to_string(&SignRequest {
                input: data,
                ..Default::default()
            })
            .unwrap_or_default(),
        )
        .await?
        .data
        .ok_or(anyhow!("vault: missing response data"))
        .map(|d| d.signature)
    }

    async fn verify<D, S>(&self, data: D, sig: S) -> Result<()>
    where
        D: Send + Sync + AsRef<[u8]>,
        S: Send + Sync + Into<String>,
    {
        self.put_endpoint::<VerifyResponse>(
            &self.ver_path,
            serde_json::to_string(&VerifyRequest {
                input: data,
                signature: sig.into(),
            })
            .unwrap_or_default(),
        )
        .await?
        .data
        .ok_or(anyhow!("vault: missing response data"))
        .and_then(|d| {
            if d.valid {
                Ok(())
            } else {
                Err(anyhow!("vault: invalid signature"))
            }
        })
    }
}

/// Helper for serialising bytes to base64.
fn as_base64<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(data.as_ref()))
}
