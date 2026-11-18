//! Safe `poll(2)` readiness wait shared by the TCP and UDP relays (unix only).
//!
//! The relays never block on their own; a single-threaded caller loop owns the wait. Because
//! one thread cannot block on two separate waits, [`wait_ready`] waits on both relays at once.
use crate::{tcp::TcpRelay, tcp::TcpSocketProtector, SocketProtector, UdpRelay};
use netscope_conntrack::FlowId;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::{io, os::fd::BorrowedFd, time::Duration};

pub(crate) type Entry<'a> = (FlowId, BorrowedFd<'a>, PollFlags);

/// Wait for `entries`; one flag per entry, true when any event (readiness, error or hangup)
/// is pending. A signal interruption reports nothing ready.
pub(crate) fn poll_entries(entries: &[Entry<'_>], wait: Duration) -> io::Result<Vec<bool>> {
    let mut fds: Vec<PollFd<'_>> = entries
        .iter()
        .map(|(_, fd, events)| PollFd::from_borrowed_fd(*fd, *events))
        .collect();
    let timeout = Timespec {
        tv_sec: wait.as_secs().min(i64::MAX as u64) as i64,
        tv_nsec: i64::from(wait.subsec_nanos()),
    };
    match poll(&mut fds, Some(&timeout)) {
        Ok(_) => Ok(fds.iter().map(|fd| !fd.revents().is_empty()).collect()),
        Err(rustix::io::Errno::INTR) => Ok(vec![false; entries.len()]),
        Err(error) => Err(error.into()),
    }
}

/// Cap `max_wait` at the earliest of the given absolute deadlines (milliseconds).
pub(crate) fn bounded_wait(now: u64, max_wait: Duration, deadlines: &[Option<u64>]) -> Duration {
    deadlines.iter().flatten().fold(max_wait, |wait, due| {
        wait.min(Duration::from_millis(due.saturating_sub(now)))
    })
}

/// Flows that should be serviced after [`wait_ready`].
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Ready {
    /// Pass to `TcpRelay::poll_ready`.
    pub tcp: Vec<FlowId>,
    /// Call `UdpRelay::receive` on each until it reports `WouldBlock`.
    pub udp: Vec<FlowId>,
}

/// Block up to `max_wait` until a TCP upstream or UDP socket is ready, or either relay has
/// time-driven work due (`TcpRelay::next_wakeup`, `UdpRelay::next_wakeup`). Returns at once when
/// the TCP relay has unprocessed client input. `now` is milliseconds. Unlike the per-relay
/// `wait_ready` methods this does not expire anything itself: call `TcpRelay::poll_ready` and
/// `UdpRelay::expire` afterwards, as in the documented loop. Cost is linear in open flows.
pub fn wait_ready<T: TcpSocketProtector, U: SocketProtector>(
    tcp: &mut TcpRelay<T>,
    udp: &mut UdpRelay<U>,
    now: u64,
    max_wait: Duration,
) -> io::Result<Ready> {
    let wait = bounded_wait(now, max_wait, &[tcp.next_wakeup(now), udp.next_wakeup()]);
    let tcp_entries = tcp.poll_entries();
    let udp_entries = udp.poll_entries();
    let entries: Vec<Entry<'_>> = tcp_entries.iter().chain(&udp_entries).copied().collect();
    let flags = poll_entries(&entries, wait)?;
    let (tcp_flags, udp_flags) = flags.split_at(tcp_entries.len());
    let pick = |entries: &[Entry<'_>], flags: &[bool]| {
        entries
            .iter()
            .zip(flags)
            .filter(|(_, ready)| **ready)
            .map(|((id, _, _), _)| *id)
            .collect()
    };
    Ok(Ready {
        tcp: pick(&tcp_entries, tcp_flags),
        udp: pick(&udp_entries, udp_flags),
    })
}
