//! Container and cloud-aware licensing
//!
//! This module provides licensing modes that work in containerized
//! and cloud environments where traditional hardware binding fails.

use crate::error::{LicenseError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Detected runtime environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeEnvironment {
    /// Traditional bare-metal or VM with stable hardware
    Standalone,
    /// Docker container
    Docker,
    /// Kubernetes pod
    Kubernetes,
    /// AWS EC2 instance
    AwsEc2,
    /// Google Cloud Compute Engine
    GcpCompute,
    /// Microsoft Azure VM
    AzureVm,
    /// Generic cloud/container (unknown provider)
    GenericCloud,
}

impl RuntimeEnvironment {
    /// Detect the current runtime environment
    pub fn detect() -> Self {
        // Check for Kubernetes
        if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            return Self::Kubernetes;
        }
        
        // Check for Docker
        if std::path::Path::new("/.dockerenv").exists() {
            return Self::Docker;
        }
        
        // Check cgroup for container indicators
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("containerd") {
                return Self::Docker;
            }
        }
        
        // Cloud provider detection would require network calls
        // For now, check environment variables that cloud providers set
        if std::env::var("AWS_EXECUTION_ENV").is_ok() || std::env::var("AWS_REGION").is_ok() {
            return Self::AwsEc2;
        }
        
        if std::env::var("GOOGLE_CLOUD_PROJECT").is_ok() || std::env::var("GCP_PROJECT").is_ok() {
            return Self::GcpCompute;
        }
        
        if std::env::var("AZURE_CLIENT_ID").is_ok() || std::env::var("WEBSITE_SITE_NAME").is_ok() {
            return Self::AzureVm;
        }
        
        Self::Standalone
    }
    
    /// Check if this environment has stable hardware identifiers
    pub fn has_stable_hardware(&self) -> bool {
        matches!(self, Self::Standalone | Self::AwsEc2 | Self::GcpCompute | Self::AzureVm)
    }
    
    /// Get the recommended instance ID source for this environment
    pub fn recommended_id_source(&self) -> Option<InstanceIdSource> {
        match self {
            Self::Standalone => None, // Use hardware binding
            Self::Docker => Some(InstanceIdSource::DockerContainerId),
            Self::Kubernetes => Some(InstanceIdSource::KubernetesPodUid),
            Self::AwsEc2 => Some(InstanceIdSource::AwsInstanceId),
            Self::GcpCompute => Some(InstanceIdSource::GcpInstanceId),
            Self::AzureVm => Some(InstanceIdSource::AzureInstanceId),
            Self::GenericCloud => Some(InstanceIdSource::CustomEnvVar("INSTANCE_ID".to_string())),
        }
    }
}

/// Source for obtaining a stable instance identifier in cloud/container environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstanceIdSource {
    /// AWS EC2 instance ID from IMDS
    AwsInstanceId,
    /// GCP instance ID from metadata server
    GcpInstanceId,
    /// Azure instance ID from IMDS
    AzureInstanceId,
    /// Kubernetes pod UID from downward API
    KubernetesPodUid,
    /// Docker container ID from cgroup
    DockerContainerId,
    /// Read from a file (e.g., mounted secret or config)
    CustomFile(PathBuf),
    /// Read from an environment variable
    CustomEnvVar(String),
}

impl InstanceIdSource {
    /// Get the instance ID from this source
    pub fn get_id(&self) -> Option<String> {
        match self {
            Self::AwsInstanceId => get_aws_instance_id(),
            Self::GcpInstanceId => get_gcp_instance_id(),
            Self::AzureInstanceId => get_azure_instance_id(),
            Self::KubernetesPodUid => get_kubernetes_pod_uid(),
            Self::DockerContainerId => get_docker_container_id(),
            Self::CustomFile(path) => {
                std::fs::read_to_string(path)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            }
            Self::CustomEnvVar(var) => {
                std::env::var(var).ok().filter(|s| !s.is_empty())
            }
        }
    }
}

/// Get AWS EC2 instance ID from Instance Metadata Service
fn get_aws_instance_id() -> Option<String> {
    // IMDSv2 with token
    let token = ureq_get_with_header(
        "http://169.254.169.254/latest/api/token",
        "X-aws-ec2-metadata-token-ttl-seconds",
        "21600",
    ).ok()?;
    
    ureq_get_with_header(
        "http://169.254.169.254/latest/meta-data/instance-id",
        "X-aws-ec2-metadata-token",
        &token,
    ).ok()
}

/// Get GCP instance ID from metadata server
fn get_gcp_instance_id() -> Option<String> {
    ureq_get_with_header(
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "Metadata-Flavor",
        "Google",
    ).ok()
}

/// Get Azure instance ID from IMDS
fn get_azure_instance_id() -> Option<String> {
    ureq_get_with_header(
        "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
        "Metadata",
        "true",
    ).ok()
}

/// Get Kubernetes pod UID from downward API
fn get_kubernetes_pod_uid() -> Option<String> {
    // Standard location when using downward API
    let paths = [
        "/etc/podinfo/uid",
        "/var/run/secrets/kubernetes.io/poduid",
    ];
    
    for path in paths {
        if let Ok(uid) = std::fs::read_to_string(path) {
            let uid = uid.trim().to_string();
            if !uid.is_empty() {
                return Some(uid);
            }
        }
    }
    
    // Fallback: try environment variable
    std::env::var("POD_UID").ok()
}

/// Get Docker container ID from cgroup
fn get_docker_container_id() -> Option<String> {
    // Read cgroup file
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    
    for line in cgroup.lines() {
        // Look for docker or containerd paths
        if let Some(pos) = line.rfind('/') {
            let id = &line[pos + 1..];
            // Container IDs are typically 64 hex characters
            if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id[..12].to_string()); // Short form
            }
        }
    }
    
    // Fallback: check hostname (often set to container ID in Docker)
    std::env::var("HOSTNAME").ok().filter(|h| {
        h.len() == 12 && h.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// Helper function for HTTP GET with a custom header
fn ureq_get_with_header(url: &str, header_name: &str, header_value: &str) -> Result<String> {
    // Use a simple blocking HTTP client
    // In production, you'd want proper async with timeouts
    
    #[cfg(feature = "cloud-metadata")]
    {
        use std::io::Read;
        use std::net::TcpStream;
        use std::io::Write;
        
        let url = url::Url::parse(url).map_err(|e| LicenseError::IoError(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        ))?;
        
        let host = url.host_str().ok_or_else(|| LicenseError::IoError(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "No host")
        ))?;
        let port = url.port().unwrap_or(80);
        
        let mut stream = TcpStream::connect_timeout(
            &format!("{}:{}", host, port).parse().unwrap(),
            Duration::from_secs(2)
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\n{}: {}\r\nConnection: close\r\n\r\n",
            url.path(),
            host,
            header_name,
            header_value
        );
        
        stream.write_all(request.as_bytes())?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        
        // Parse HTTP response (very basic)
        if let Some(body_start) = response.find("\r\n\r\n") {
            return Ok(response[body_start + 4..].trim().to_string());
        }
    }
    
    Err(LicenseError::IoError(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Cloud metadata feature not enabled"
    )))
}

/// Container-aware license binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerBinding {
    /// The detected environment
    pub environment: RuntimeEnvironment,
    /// The instance ID source used
    pub id_source: Option<InstanceIdSource>,
    /// The bound instance ID (hashed)
    pub instance_id_hash: Option<String>,
}

impl ContainerBinding {
    /// Create a new container binding for the current environment
    pub fn detect() -> Self {
        let environment = RuntimeEnvironment::detect();
        let id_source = environment.recommended_id_source();
        
        let instance_id_hash = id_source.as_ref()
            .and_then(|src| src.get_id())
            .map(|id| sha256_short(&id));
        
        Self {
            environment,
            id_source,
            instance_id_hash,
        }
    }
    
    /// Check if the current environment matches this binding
    pub fn matches_current(&self) -> bool {
        if self.instance_id_hash.is_none() {
            // No binding set
            return true;
        }
        
        let current = Self::detect();
        self.instance_id_hash == current.instance_id_hash
    }
    
    /// Check if hardware binding should be used instead
    pub fn should_use_hardware_binding(&self) -> bool {
        self.environment.has_stable_hardware() && self.instance_id_hash.is_none()
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_environment_detection() {
        let env = RuntimeEnvironment::detect();
        // In a test environment, should be Standalone or Docker depending on CI
        println!("Detected environment: {:?}", env);
    }
    
    #[test]
    fn test_custom_env_var_source() {
        std::env::set_var("TEST_INSTANCE_ID", "test-id-12345");
        
        let source = InstanceIdSource::CustomEnvVar("TEST_INSTANCE_ID".to_string());
        let id = source.get_id();
        
        assert_eq!(id, Some("test-id-12345".to_string()));
        
        std::env::remove_var("TEST_INSTANCE_ID");
    }
    
    #[test]
    fn test_container_binding() {
        let binding = ContainerBinding::detect();
        
        // Should match itself
        assert!(binding.matches_current());
        
        println!("Container binding: {:?}", binding);
    }
}
