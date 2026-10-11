// Licensed under the MIT License.

use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};

use crate::mxc_common::models::{ContainmentBackend, ExecutionRequest};
use crate::{Error, ErrorCode};

pub(crate) fn validate(request: &ExecutionRequest) -> Result<(), Error> {
    if request.inherited_handles.is_empty() {
        return Ok(());
    }
    if request.containment != ContainmentBackend::ProcessContainer {
        return Err(Error::new(
            ErrorCode::UnsupportedContainment,
            "inherited handles require Windows ProcessContainer",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for owned in &request.inherited_handles {
        let handle = HANDLE(owned.as_raw_handle());
        if handle.is_invalid() || !seen.insert(handle.0 as usize) {
            return Err(Error::new(
                ErrorCode::MalformedRequest,
                "inherited handles must be valid and distinct",
            ));
        }
        let mut flags = 0;
        // SAFETY: Arc<OwnedHandle> keeps the handle open during validation.
        unsafe { GetHandleInformation(handle, &mut flags) }.map_err(|error| {
            Error::new(
                ErrorCode::BackendError,
                format!("failed to inspect inherited handle: {error}"),
            )
        })?;
        if flags & HANDLE_FLAG_INHERIT.0 == 0 {
            return Err(Error::new(
                ErrorCode::MalformedRequest,
                "inherited handles must have HANDLE_FLAG_INHERIT set in the parent",
            ));
        }
    }
    Ok(())
}
