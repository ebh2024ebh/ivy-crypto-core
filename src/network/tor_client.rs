use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

use crate::LatticeError;

/// Arti-based Tor client for onion-routed message transport.
pub struct LatticeTorClient {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl LatticeTorClient {
    /// Bootstrap a new Tor connection.
    ///
    /// `data_dir` must be a writable directory. On Android this is
    /// `context.filesDir + "/tor_data"`. Arti requires separate cache and
    /// state subdirectories; we create them under `data_dir`.
    pub async fn connect(data_dir: &str) -> Result<Self, LatticeError> {
        let cache_dir = format!("{}/cache", data_dir);
        let state_dir = format!("{}/state", data_dir);
        std::fs::create_dir_all(&cache_dir).ok();
        std::fs::create_dir_all(&state_dir).ok();

        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .cache_dir(arti_client::config::CfgPath::new(cache_dir))
            .state_dir(arti_client::config::CfgPath::new(state_dir));

        let config = builder
            .build()
            .map_err(|e| LatticeError::TorConnectionFailed(format!("config build: {}", e)))?;

        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| LatticeError::TorConnectionFailed(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// Send a message payload through a Tor circuit to a destination onion address.
    pub async fn send_message(
        &self,
        destination: &str,
        port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, LatticeError> {
        let mut stream = self
            .client
            .connect((destination, port))
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;

        // Send length-prefixed payload
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream
            .write_all(&len_bytes)
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;
        stream
            .write_all(payload)
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;

        // Read response
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;
        let response_len = u32::from_be_bytes(len_buf) as usize;

        if response_len > 10 * 1024 * 1024 {
            return Err(LatticeError::NetworkError("Response too large".into()));
        }

        let mut response = vec![0u8; response_len];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;

        Ok(response)
    }

    /// Send a raw payload (no length prefix) over Tor and read back the
    /// full response until EOF. Used for HTTP/1.1 with `Connection: close`
    /// where the server signals end-of-response by half-closing the stream.
    ///
    /// The cap is the same 10 MiB ceiling as [send_message] to prevent a
    /// malicious hidden service from exhausting client memory.
    pub async fn send_http(
        &self,
        destination: &str,
        port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, LatticeError> {
        let mut stream = self
            .client
            .connect((destination, port))
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;

        stream
            .write_all(payload)
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| LatticeError::NetworkError(e.to_string()))?;

        // Read until EOF, capped at 10 MiB defensively.
        const MAX_RESPONSE: usize = 10 * 1024 * 1024;
        let mut response = Vec::with_capacity(8 * 1024);
        let mut buf = [0u8; 8 * 1024];
        loop {
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| LatticeError::NetworkError(e.to_string()))?;
            if n == 0 {
                break;
            }
            if response.len() + n > MAX_RESPONSE {
                return Err(LatticeError::NetworkError("HTTP response too large".into()));
            }
            response.extend_from_slice(&buf[..n]);
        }

        Ok(response)
    }

    /// Clone the underlying Arc<TorClient>. Cheap; the handle is shared.
    pub fn clone_handle(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
        }
    }

    /// Check if the Tor client is connected and has circuits available.
    pub fn is_connected(&self) -> bool {
        // BootstrapStatus in 0.24 exposes as_frac() returning 0.0-1.0
        let status = self.client.bootstrap_status();
        status.as_frac() >= 1.0
    }
}
