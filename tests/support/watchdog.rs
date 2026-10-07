// SPDX-License-Identifier: MIT OR Apache-2.0

//! A deadline for a test that could loop forever: a test that runs past it aborts the whole
//! test process with a message, rather than spin a core until someone notices.

use std::io::Write as _;
use std::sync::mpsc;
use std::time::Duration;

/// Arms a deadline of `secs` for `what`; dropping the returned guard disarms it.
pub fn watchdog(secs: u64, what: &'static str) -> mpsc::Sender<()> {
    let (disarm, armed) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(mpsc::RecvTimeoutError::Timeout) = armed.recv_timeout(Duration::from_secs(secs))
        {
            // Straight to the stream: the harness captures `eprintln!` and an abort loses it.
            let _ = writeln!(
                std::io::stderr(),
                "watchdog: {what} ran past {secs} s; aborting the test process"
            );
            std::process::abort();
        }
    });
    disarm
}
