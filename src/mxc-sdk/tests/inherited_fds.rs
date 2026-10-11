// Licensed under the MIT License.

#![cfg(unix)]

#[cfg(target_os = "macos")]
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use mxc_sdk::v1::{spawn_with_inherited_fds, ContainerRequest, Containment, ErrorCode};

#[test]
fn unsupported_backend_rejects_inherited_capabilities_before_spawning() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let request = ContainerRequest {
        containment: Containment::Bubblewrap,
        ..ContainerRequest::new("exit 0")
    };
    let error =
        spawn_with_inherited_fds(request, Default::default(), vec![Arc::new(socket.into())])
            .err()
            .expect("unsupported inherited capabilities must fail closed");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment);
}

#[cfg(target_os = "macos")]
mod seatbelt {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use mxc_sdk::v1::{spawn, FilesystemPolicy, WaitResult};

    fn request(command: &str) -> ContainerRequest {
        ContainerRequest {
            filesystem: Some(FilesystemPolicy {
                readwrite_paths: vec!["/tmp".into()],
                ..Default::default()
            }),
            timeout_ms: Some(10_000),
            ..ContainerRequest::new(command)
        }
    }

    fn flags(fd: &OwnedFd) -> i32 {
        // SAFETY: The caller owns the descriptor.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        flags
    }

    #[test]
    fn only_selected_channels_reach_the_sandbox_and_parent_flags_stay_unchanged() {
        let (mut input, child_input) = UnixStream::pair().unwrap();
        let (mut output, child_output) = UnixStream::pair().unwrap();
        let (unselected, mut unselected_peer) = UnixStream::pair().unwrap();
        let child_input: Arc<OwnedFd> = Arc::new(child_input.into());
        let child_output: Arc<OwnedFd> = Arc::new(child_output.into());
        let unselected: OwnedFd = unselected.into();
        let before = (
            flags(&child_input),
            flags(&child_output),
            flags(&unselected),
        );
        assert_ne!(before.0 & libc::FD_CLOEXEC, 0);
        assert_ne!(before.1 & libc::FD_CLOEXEC, 0);
        assert_ne!(before.2 & libc::FD_CLOEXEC, 0);
        let check_unselected = format!(
            "(printf leaked >&{}) 2>/dev/null || true",
            unselected.as_raw_fd()
        );
        let script = format!(
            "{check_unselected}; IFS= read -r message <&{}; printf 'reply:%s\\n' \"$message\" >&{}",
            child_input.as_raw_fd(),
            child_output.as_raw_fd(),
        );
        let mut process = spawn_with_inherited_fds(
            request(&script),
            Default::default(),
            vec![Arc::clone(&child_input), Arc::clone(&child_output)],
        )
        .unwrap();
        assert_eq!(flags(&child_input), before.0);
        assert_eq!(flags(&child_output), before.1);
        assert_eq!(flags(&unselected), before.2);
        // A separate spawn must not inherit channels used by the prepared child.
        let mut unrelated = spawn(
            request(&format!(
                "(printf leaked >&{}) 2>/dev/null || true",
                child_output.as_raw_fd()
            )),
            Default::default(),
        )
        .unwrap();
        assert_eq!(unrelated.wait().unwrap(), WaitResult::Exited(0));
        drop(child_input);
        drop(child_output);
        output
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        input.write_all(b"hello\n").unwrap();
        let mut reply = String::new();
        output.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "reply:hello\n");
        assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
        // Shells may reuse a closed number internally; verify the socket, not just its number.
        unselected_peer.set_nonblocking(true).unwrap();
        assert_eq!(
            unselected_peer.read(&mut [0; 32]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
        );
    }

    #[test]
    fn duplicate_descriptors_are_rejected() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let socket: Arc<OwnedFd> = Arc::new(socket.into());
        let error = spawn_with_inherited_fds(
            request("exit 0"),
            Default::default(),
            vec![Arc::clone(&socket), socket],
        )
        .err()
        .expect("duplicate descriptors must be rejected");
        assert_eq!(error.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn launch_lock_remains_held_with_ipc_after_parent_releases_its_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("launch.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let lock: Arc<OwnedFd> = Arc::new(file.into());
        // SAFETY: The test owns both the lock and the later independent candidate.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let (mut host, socket) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let socket: Arc<OwnedFd> = Arc::new(socket.into());
        let mut process = spawn_with_inherited_fds(
            request(&format!(
                "printf ready >&{}; IFS= read -r done <&{}",
                socket.as_raw_fd(),
                socket.as_raw_fd(),
            )),
            Default::default(),
            vec![Arc::clone(&lock), socket],
        )
        .unwrap();
        let mut ready = [0; 5];
        host.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready");
        drop(lock);
        let candidate = std::fs::File::open(path).unwrap();
        assert_eq!(
            unsafe { libc::flock(candidate.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        host.write_all(b"done\n").unwrap();
        assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
        // Parallel spawns can briefly hold the parent's CLOEXEC descriptors before exec.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::flock(candidate.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EWOULDBLOCK)
            );
            assert!(
                std::time::Instant::now() < deadline,
                "launch lock remained held after child exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn descriptors_without_close_on_exec_are_rejected_without_changing_flags() {
        const ISOLATED: &str = "MONA_MXC_ISOLATED_FD_TEST";
        if std::env::var_os(ISOLATED).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "seatbelt::descriptors_without_close_on_exec_are_rejected_without_changing_flags",
                    "--test-threads=1",
                ])
                .env(ISOLATED, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let (socket, _peer) = UnixStream::pair().unwrap();
        let socket: Arc<OwnedFd> = Arc::new(socket.into());
        let before = flags(&socket) & !libc::FD_CLOEXEC;
        // SAFETY: This test exclusively owns the socket and does not spawn until validated.
        assert_eq!(
            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, before) },
            0
        );
        let result = spawn_with_inherited_fds(
            request("exit 0"),
            Default::default(),
            vec![Arc::clone(&socket)],
        );
        let after = flags(&socket);
        // Restore immediately so parallel tests cannot inherit this test descriptor later.
        assert_eq!(
            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, before | libc::FD_CLOEXEC) },
            0
        );
        assert_eq!(result.err().unwrap().code, ErrorCode::MalformedRequest);
        assert_eq!(after, before);
    }
}
