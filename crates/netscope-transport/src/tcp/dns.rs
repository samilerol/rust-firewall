//! One bounded frame in each direction. No unvalidated prefix is forwarded.
use super::{retry, Error, StackSocket};
use crate::{dns_pending::PendingQueries, DnsError};
use netscope_conntrack::FlowId;
use netscope_dns::{parse_query, parse_response, DomainPolicy, MAX_MESSAGE};
use netscope_policy::Action;
use std::io::{Read, Write};

pub(super) const FRAME_BYTES: usize = MAX_MESSAGE + 2;
pub(super) const RESERVED_BYTES: usize = 2 * FRAME_BYTES;
struct Frame {
    bytes: Vec<u8>,
    written: usize,
    checked: bool,
    id: u16,
    started: Option<u64>,
}
impl Frame {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(FRAME_BYTES),
            written: 0,
            checked: false,
            id: 0,
            started: None,
        }
    }
    fn target(&self) -> usize {
        if self.bytes.len() < 2 {
            2
        } else {
            2 + usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]]))
        }
    }
    fn full(&self) -> bool {
        self.bytes.len() >= 2 && self.bytes.len() == self.target()
    }
    fn check_length(&self) -> Result<(), Error> {
        if self.bytes.len() >= 2 && !(12..=MAX_MESSAGE).contains(&(self.target() - 2)) {
            return Err(Error::Dns(DnsError::FrameLength));
        }
        Ok(())
    }
    fn feed(&mut self, bytes: &[u8], now: u64) -> (usize, Result<(), Error>) {
        let mut used = 0;
        // At most a prefix and one body, never consume a following coalesced frame.
        for _ in 0..2 {
            let count = (self.target() - self.bytes.len()).min(bytes.len() - used);
            if count == 0 {
                break;
            }
            self.started.get_or_insert(now);
            self.bytes.extend_from_slice(&bytes[used..used + count]);
            used += count;
            if let Err(error) = self.check_length() {
                return (used, Err(error));
            }
        }
        (used, Ok(()))
    }
    fn read_once(&mut self, source: &mut impl Read, now: u64) -> Result<bool, Error> {
        let old = self.bytes.len();
        self.bytes.resize(self.target(), 0);
        let result = source.read(&mut self.bytes[old..]);
        let count = match result {
            Ok(count) => count,
            Err(error) => {
                self.bytes.truncate(old);
                return if retry(&error) {
                    Ok(false)
                } else {
                    Err(error.into())
                };
            }
        };
        self.bytes.truncate(old + count);
        if count > 0 {
            self.started.get_or_insert(now);
        }
        self.check_length()?;
        if count == 0 && !self.bytes.is_empty() {
            return Err(Error::Dns(DnsError::IncompleteFrame));
        }
        Ok(count == 0)
    }
    fn write_once(&mut self, target: &mut impl Write) -> Result<(), Error> {
        debug_assert!(self.full() && self.checked);
        match target.write(&self.bytes[self.written..]) {
            Ok(0) => Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "zero DNS frame write",
            )
            .into()),
            Ok(count) => {
                self.written += count;
                Ok(())
            }
            Err(error) if retry(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn done(&self) -> bool {
        self.full() && self.written == self.bytes.len()
    }
    fn clear(&mut self) {
        self.bytes.clear();
        self.written = 0;
        self.checked = false;
        self.started = None;
    }
    fn expired(&self, now: u64, timeout: u64) -> bool {
        self.started.is_some_and(|start| now - start >= timeout)
    }
}
pub(super) struct DnsStream {
    outbound: Frame,
    inbound: Frame,
}
impl DnsStream {
    pub(super) fn new() -> Self {
        Self {
            outbound: Frame::new(),
            inbound: Frame::new(),
        }
    }
    pub(super) fn used(&self) -> usize {
        self.outbound.bytes.len() + self.inbound.bytes.len()
    }
    pub(super) fn outbound_empty(&self) -> bool {
        self.outbound.bytes.is_empty()
    }
    pub(super) fn expired(&self, now: u64, timeout: u64) -> bool {
        self.outbound.expired(now, timeout) || self.inbound.expired(now, timeout)
    }
    fn validate_query(
        &mut self,
        id: FlowId,
        policy: &DomainPolicy,
        pending: &mut PendingQueries,
        now: u64,
    ) -> Result<(), Error> {
        let frame = &mut self.outbound;
        let query =
            parse_query(&frame.bytes[2..]).map_err(|e| Error::Dns(DnsError::Malformed(e)))?;
        let decision = policy.decide(&query.question.name);
        if decision.action == Action::Deny {
            return Err(Error::Dns(DnsError::DomainDenied {
                rule_index: decision.rule_index,
            }));
        }
        // TCP application retries are distinct frames: IDs must be unique while pending.
        if pending.contains(&id, query.id) {
            return Err(Error::Dns(DnsError::Busy));
        }
        pending.check(&id, &query).map_err(Error::Dns)?;
        pending.record(id, query, now);
        frame.checked = true;
        Ok(())
    }
    fn validate_response(
        &mut self,
        id: FlowId,
        policy: &DomainPolicy,
        pending: &PendingQueries,
    ) -> Result<(), Error> {
        let frame = &mut self.inbound;
        let response =
            parse_response(&frame.bytes[2..]).map_err(|e| Error::Dns(DnsError::Malformed(e)))?;
        pending.matches(&id, &response).map_err(Error::Dns)?;
        let decision = policy.decide(&response.question.name);
        if decision.action == Action::Deny {
            return Err(Error::Dns(DnsError::DomainDenied {
                rule_index: decision.rule_index,
            }));
        }
        frame.checked = true;
        frame.id = response.id;
        Ok(())
    }
    /// At most one OS write/read and one complete frame per direction per pass.
    pub(super) fn pump(
        &mut self,
        socket: &mut StackSocket,
        upstream: &mut (impl Read + Write),
        context: DnsContext<'_>,
        read_upstream: bool,
    ) -> Result<bool, Error> {
        let DnsContext {
            id,
            policy,
            pending,
            now,
        } = context;
        if !self.outbound.full() && socket.can_recv() {
            if let Ok(result) = socket.recv(|bytes| self.outbound.feed(bytes, now)) {
                result?;
            }
        }
        if self.outbound.full() {
            if !self.outbound.checked {
                self.validate_query(id, policy, pending, now)?;
            }
            self.outbound.write_once(upstream)?;
            if self.outbound.done() {
                self.outbound.clear();
            }
        }
        if socket.recv_queue() == 0
            && !socket.may_recv()
            && !self.outbound.bytes.is_empty()
            && !self.outbound.full()
        {
            return Err(Error::Dns(DnsError::IncompleteFrame));
        }
        let eof = if !self.inbound.full() && read_upstream {
            self.inbound.read_once(upstream, now)?
        } else {
            false
        };
        if self.inbound.full() {
            if !self.inbound.checked {
                self.validate_response(id, policy, pending)?;
            }
            if socket.can_send() {
                self.inbound.written += socket
                    .send_slice(&self.inbound.bytes[self.inbound.written..])
                    .map_err(|_| Error::Stack)?;
                if self.inbound.done() {
                    pending.remove_query(&id, self.inbound.id);
                    self.inbound.clear();
                }
            }
        }
        Ok(eof)
    }
}
pub(super) struct DnsContext<'a> {
    pub id: FlowId,
    pub policy: &'a DomainPolicy,
    pub pending: &'a mut PendingQueries,
    pub now: u64,
}

#[cfg(any(test, feature = "fuzzing"))]
mod harness {
    use super::*;
    use crate::DnsLimits;
    use netscope_packet::Protocol;
    use std::io::{self, Cursor};
    pub(super) struct ScheduledIo {
        source: Cursor<Vec<u8>>,
        pub(super) output: Vec<u8>,
        calls: usize,
        chunk: usize,
    }
    impl ScheduledIo {
        fn step(&mut self) -> io::Result<()> {
            self.calls += 1;
            match self.calls % 5 {
                0 => Err(io::ErrorKind::WouldBlock.into()),
                1 => Err(io::ErrorKind::Interrupted.into()),
                _ => Ok(()),
            }
        }
    }
    impl Read for ScheduledIo {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.step()?;
            let len = bytes.len().min(self.chunk);
            self.source.read(&mut bytes[..len])
        }
    }
    impl Write for ScheduledIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.step()?;
            let n = bytes.len().min(self.chunk);
            self.output.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    pub(super) fn exercise(input: &[u8]) {
        // Test hostile length/data chunking separately from guaranteed valid transactions.
        let mut frame = Frame::new();
        let mut consumed = 0;
        for chunk in input.chunks(1 + usize::from(input.first().copied().unwrap_or(0) % 31)) {
            let (n, result) = frame.feed(chunk, 0);
            consumed += n;
            assert!(n <= chunk.len());
            assert!(frame.bytes.len() <= FRAME_BYTES);
            if result.is_err() || frame.full() {
                break;
            }
        }
        assert_eq!(&frame.bytes, &input[..consumed]);
        if frame.full() {
            let _ = parse_query(&frame.bytes[2..]);
            let _ = parse_response(&frame.bytes[2..]);
        }
        let id = FlowId {
            source: "192.0.2.1".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            source_port: 12345,
            destination_port: 53,
            protocol: Protocol::Tcp,
        };
        let mut wire = vec![
            0, 19, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        if input.first().copied().unwrap_or(0) & 1 != 0 {
            wire[15] = b'b';
        }
        let policy = DomainPolicy::new(vec![], Action::Allow).unwrap();
        let mut pending = PendingQueries::new(DnsLimits {
            max_pending_per_flow: 2,
            max_pending_total: 2,
            query_timeout: 10,
        });
        let mut stream = DnsStream::new();
        let mut source = ScheduledIo {
            source: Cursor::new(wire.clone()),
            output: vec![],
            calls: 0,
            chunk: 1 + usize::from(input.get(1).copied().unwrap_or(0) % 31),
        };
        for _ in 0..128 {
            assert!(!stream.outbound.read_once(&mut source, 0).unwrap());
            if stream.outbound.full() {
                break;
            }
        }
        assert!(stream.outbound.full());
        stream.validate_query(id, &policy, &mut pending, 0).unwrap();
        assert_eq!(pending.len(), 1);
        for _ in 0..128 {
            let before = source.output.len();
            stream.outbound.write_once(&mut source).unwrap();
            assert_eq!(stream.outbound.written, source.output.len());
            assert!(source.output.len() >= before);
            if stream.outbound.done() {
                break;
            }
        }
        assert!(stream.outbound.done());
        assert_eq!(source.output, wire);
        // Reverse framing is validated before a delivery offset can advance.
        wire[4..6].copy_from_slice(&0x8180u16.to_be_bytes());
        stream.inbound.feed(&wire, 1).1.unwrap();
        stream.validate_response(id, &policy, &pending).unwrap();
        assert!(stream.inbound.checked);
        assert_eq!(stream.inbound.written, 0);
        assert_eq!(stream.inbound.id, 0x1234);
    }
}
#[cfg(feature = "fuzzing")]
pub(super) fn exercise(input: &[u8]) {
    harness::exercise(input);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_partial_io_and_retry_schedules_preserve_exact_bytes() {
        for n in 0..32 {
            harness::exercise(&[n, n]);
        }
        for input in [
            &[][..],
            &[0][..],
            &[0, 0][..],
            &[255, 255][..],
            &[0, 12, 0, 0, 0][..],
        ] {
            harness::exercise(input);
        }
    }
    #[test]
    fn every_split_preserves_prefix_body_and_coalesced_remainder() {
        let wire = [0, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        for split in 0..=wire.len() {
            let mut frame = Frame::new();
            assert_eq!(frame.feed(&wire[..split], 0).0, split);
            let mut rest = wire[split..].to_vec();
            rest.extend_from_slice(&wire);
            let (used, result) = frame.feed(&rest, 0);
            result.unwrap();
            assert_eq!(used, wire.len() - split);
            assert_eq!(frame.bytes, wire);
            assert!(frame.full());
            assert_eq!(&rest[used..], wire);
        }
    }
}
