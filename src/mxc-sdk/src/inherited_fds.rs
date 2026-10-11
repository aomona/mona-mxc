// Licensed under the MIT License.

use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use crate::mxc_common::models::{ContainmentBackend, ExecutionRequest, LaunchMethod};
use crate::{Error, ErrorCode};

pub(crate) fn validate(request: &ExecutionRequest) -> Result<(), Error> {
    if request.inherited_fds.is_empty() {
        return Ok(());
    }
    let supported = (cfg!(target_os = "linux")
        && request.containment == ContainmentBackend::Bubblewrap)
        || (cfg!(target_os = "macos")
            && request.containment == ContainmentBackend::Seatbelt
            && !request
                .seatbelt
                .as_ref()
                .is_some_and(|config| config.launch_method != LaunchMethod::Exec));
    if !supported {
        return Err(Error::new(
            ErrorCode::UnsupportedContainment,
            "inherited descriptors require Linux Bubblewrap or macOS Seatbelt direct execution",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for owned in &request.inherited_fds {
        let fd = owned.as_raw_fd();
        if fd < 3 || !seen.insert(fd) {
            return Err(Error::new(
                ErrorCode::MalformedRequest,
                "inherited descriptors must be distinct and must not replace standard streams",
            ));
        }
        // SAFETY: Arc<OwnedFd> keeps this descriptor open during validation.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(Error::new(
                ErrorCode::BackendError,
                format!(
                    "failed to inspect inherited descriptor: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        if flags & libc::FD_CLOEXEC == 0 {
            return Err(Error::new(
                ErrorCode::MalformedRequest,
                "inherited descriptors must have FD_CLOEXEC set in the parent",
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn configure(command: &mut std::process::Command, fds: &[Arc<OwnedFd>]) {
    use std::os::unix::process::CommandExt;

    if fds.is_empty() {
        return;
    }
    let fds = fds.to_vec();
    // SAFETY: Only fcntl runs after fork; the closure owns all descriptors.
    // No remapping means stdio and Command's internal error pipe cannot collide.
    unsafe {
        command.pre_exec(move || {
            for owned in &fds {
                let fd = owned.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_capabilities_are_not_serialized() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let request = ExecutionRequest {
            inherited_fds: vec![Arc::new(socket.into())],
            ..Default::default()
        };
        let json = serde_json::to_value(request).unwrap();
        assert!(json.get("inherited_fds").is_none());
    }

    #[test]
    fn policy_hash_tracks_channel_count_not_descriptor_numbers() {
        use crate::mxc_common::policy_identity::policy_hash;

        let mut request = ExecutionRequest::default();
        let without_channels = policy_hash(&request);
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        request.inherited_fds.push(Arc::new(socket.into()));
        let one_channel = policy_hash(&request);
        assert_ne!(without_channels, one_channel);
        let (other, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        request.inherited_fds[0] = Arc::new(other.into());
        assert_eq!(one_channel, policy_hash(&request));
        let (extra, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        request.inherited_fds.push(Arc::new(extra.into()));
        assert_ne!(one_channel, policy_hash(&request));
    }
}
