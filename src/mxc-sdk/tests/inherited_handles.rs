// Licensed under the MIT License.

#![cfg(windows)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mxc_sdk::v1::{
    spawn_with_inherited_handles, ContainerRequest, Containment, ErrorCode, FilesystemPolicy,
    WaitResult,
};
use windows::Win32::Foundation::{
    GetHandleInformation, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};

fn pipe() -> (File, File) {
    let mut reader = HANDLE::default();
    let mut writer = HANDLE::default();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: true.into(),
        ..Default::default()
    };
    // SAFETY: The resulting handles are uniquely transferred into File owners.
    unsafe {
        CreatePipe(&mut reader, &mut writer, Some(&attributes), 0).unwrap();
        (
            File::from_raw_handle(reader.0),
            File::from_raw_handle(writer.0),
        )
    }
}

fn flags(handle: &impl AsRawHandle) -> u32 {
    let mut flags = 0;
    unsafe { GetHandleInformation(HANDLE(handle.as_raw_handle()), &mut flags) }.unwrap();
    flags
}

fn available(reader: &File) -> u32 {
    let mut count = 0;
    unsafe {
        PeekNamedPipe(
            HANDLE(reader.as_raw_handle()),
            None,
            0,
            None,
            Some(&mut count),
            None,
        )
    }
    .unwrap();
    count
}

#[test]
fn duplicate_and_noninheritable_handles_are_rejected_without_changing_flags() {
    let handle: Arc<OwnedHandle> = Arc::new(tempfile::tempfile().unwrap().into());
    let before = flags(handle.as_ref());
    assert_eq!(before & HANDLE_FLAG_INHERIT.0, 0);
    let error = spawn_with_inherited_handles(
        ContainerRequest::new("cmd /c exit 0"),
        Default::default(),
        vec![Arc::clone(&handle)],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::MalformedRequest);
    assert_eq!(flags(handle.as_ref()), before);
    unsafe {
        SetHandleInformation(
            HANDLE(handle.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .unwrap();
    let error = spawn_with_inherited_handles(
        ContainerRequest::new("cmd /c exit 0"),
        Default::default(),
        vec![Arc::clone(&handle), Arc::clone(&handle)],
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::MalformedRequest);
}

#[test]
fn unsupported_backend_rejects_inherited_capabilities() {
    let (_, writer) = pipe();
    let request = ContainerRequest {
        containment: Containment::Bubblewrap,
        ..ContainerRequest::new("cmd /c exit 0")
    };
    let error =
        spawn_with_inherited_handles(request, Default::default(), vec![Arc::new(writer.into())])
            .err()
            .unwrap();
    assert_eq!(error.code, ErrorCode::UnsupportedContainment);
}

#[test]
fn capabilities_are_not_serialized_and_policy_hash_tracks_only_count() {
    use mxc_sdk::mxc_common::{models::ExecutionRequest, policy_identity::policy_hash};
    let mut request = ExecutionRequest::default();
    let without = policy_hash(&request);
    request
        .inherited_handles
        .push(Arc::new(tempfile::tempfile().unwrap().into()));
    let one = policy_hash(&request);
    assert_ne!(without, one);
    let json = serde_json::to_value(&request).unwrap();
    assert!(json.get("inherited_handles").is_none());
    request.inherited_handles[0] = Arc::new(tempfile::tempfile().unwrap().into());
    assert_eq!(one, policy_hash(&request));
    request
        .inherited_handles
        .push(Arc::new(tempfile::tempfile().unwrap().into()));
    assert_ne!(one, policy_hash(&request));
}

#[test]
fn child_ipc() {
    let Ok(values) = std::env::var("MONA_MXC_CHILD_HANDLES") else {
        return;
    };
    let handles: Vec<usize> = values.split(',').map(|v| v.parse().unwrap()).collect();
    assert_eq!(handles.len(), 3);
    // A failed write is fine; the host checks that its unselected pipe receives nothing.
    let mut written = 0;
    let _ = unsafe {
        WriteFile(
            HANDLE(handles[2] as _),
            Some(b"leaked"),
            Some(&mut written),
            None,
        )
    };
    if handles[0] == 0 {
        return;
    }
    // SAFETY: These are the selected handles inherited into this child only.
    let mut input = unsafe { File::from_raw_handle(handles[0] as _) };
    let mut output = unsafe { File::from_raw_handle(handles[1] as _) };
    output.write_all(b"ready").unwrap();
    let mut message = String::new();
    input.read_to_string(&mut message).unwrap();
    assert_eq!(message, "hello");
    output.write_all(b"reply:hello").unwrap();
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows ProcessContainer host"]
fn selected_ipc_and_launch_lock_reach_processcontainer_without_unselected_handles() {
    let exe = std::env::current_exe().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("launch.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let lock: Arc<OwnedHandle> = Arc::new(lock.into());
    unsafe {
        SetHandleInformation(
            HANDLE(lock.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .unwrap();
    let (input, mut host_input) = pipe();
    let (mut host_output, output) = pipe();
    for host in [&host_input, &host_output] {
        unsafe {
            SetHandleInformation(
                HANDLE(host.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAGS(0),
            )
        }
        .unwrap();
    }
    let input: Arc<OwnedHandle> = Arc::new(input.into());
    let output: Arc<OwnedHandle> = Arc::new(output.into());
    let (unselected_reader, unselected_writer) = pipe();
    let before = (
        flags(input.as_ref()),
        flags(output.as_ref()),
        flags(lock.as_ref()),
    );
    let command = format!(
        "\"{}\" --exact child_ipc --nocapture --test-threads=1",
        exe.display()
    );
    let request = ContainerRequest {
        environment: Some(vec![(
            "MONA_MXC_CHILD_HANDLES".into(),
            format!(
                "{},{},{}",
                input.as_raw_handle() as usize,
                output.as_raw_handle() as usize,
                unselected_writer.as_raw_handle() as usize
            ),
        )]),
        inherit_default_environment: Some(true),
        filesystem: Some(FilesystemPolicy {
            readonly_paths: vec![exe.parent().unwrap().to_string_lossy().into_owned()],
            ..Default::default()
        }),
        timeout_ms: Some(30_000),
        ..ContainerRequest::new(command)
    };
    let mut process = spawn_with_inherited_handles(
        request.clone(),
        Default::default(),
        vec![Arc::clone(&input), Arc::clone(&output), Arc::clone(&lock)],
    )
    .unwrap();
    assert_eq!(
        (
            flags(input.as_ref()),
            flags(output.as_ref()),
            flags(lock.as_ref())
        ),
        before
    );
    drop(input);
    drop(output);
    drop(lock);
    let deadline = Instant::now() + Duration::from_secs(30);
    while available(&host_output) < 5 {
        assert!(Instant::now() < deadline, "child did not signal readiness");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut ready = [0; 5];
    host_output.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    assert!(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .is_err(),
        "child must retain the exclusive launch lock"
    );
    host_input.write_all(b"hello").unwrap();
    drop(host_input);
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    let mut reply = String::new();
    host_output.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "reply:hello");
    assert_eq!(available(&unselected_reader), 0);
    assert!(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .is_ok());
    // Positive control: the same probe must write when the handle is selected.
    let mut request = request;
    request.environment = Some(vec![(
        "MONA_MXC_CHILD_HANDLES".into(),
        format!("0,0,{}", unselected_writer.as_raw_handle() as usize),
    )]);
    let mut control = spawn_with_inherited_handles(
        request,
        Default::default(),
        vec![Arc::new(unselected_writer.into())],
    )
    .unwrap();
    assert_eq!(control.wait().unwrap(), WaitResult::Exited(0));
    let mut message = String::new();
    let mut unselected_reader = unselected_reader;
    unselected_reader.read_to_string(&mut message).unwrap();
    assert_eq!(message, "leaked");
}

#[test]
fn helper_process_does_not_inherit_unselected_handles() {
    const ISOLATED: &str = "MONA_MXC_ISOLATED_HANDLE_TEST";
    if std::env::var_os(ISOLATED).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "helper_process_does_not_inherit_unselected_handles",
                "--test-threads=1",
            ])
            .env(ISOLATED, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (reader, writer) = pipe();
    std::env::set_var(
        "MONA_MXC_CHILD_HANDLES",
        format!("0,0,{}", writer.as_raw_handle() as usize),
    );
    let command = format!(
        "\"{}\" --exact child_ipc --nocapture --test-threads=1",
        std::env::current_exe().unwrap().display()
    );
    let output =
        mxc_sdk::mxc_common::process_util::run_process_with_captured_output(None, &command, 10_000)
            .unwrap();
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(available(&reader), 0);
}
