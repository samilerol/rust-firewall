//! In-memory raw-IP device. One ingress slot, explicitly bounded egress packet slots.
use smoltcp::{
    phy::{Device as PhyDevice, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use std::collections::VecDeque;
pub(crate) struct Device {
    pub rx: Option<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
    pub mtu: usize,
    pub slots: usize,
}
impl Device {
    pub fn new(mtu: usize, slots: usize) -> Self {
        Self {
            rx: None,
            tx: VecDeque::new(),
            mtu,
            slots,
        }
    }
    pub fn available(&self) -> bool {
        self.tx.len() < self.slots
    }
}
pub struct Rx(Vec<u8>);
pub struct Tx<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        // smoltcp's Device contract bounds emitted IP packets by capabilities.MTU.
        // Fail rather than allocate above the configured budget if that dependency contract breaks.
        assert!(len <= self.mtu, "TCP stack emitted above device MTU");
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.queue.push_back(packet);
        result
    }
}
impl PhyDevice for Device {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if !self.available() {
            return None;
        }
        let packet = self.rx.take()?;
        Some((
            Rx(packet),
            Tx {
                queue: &mut self.tx,
                mtu: self.mtu,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        if !self.available() {
            return None;
        }
        Some(Tx {
            queue: &mut self.tx,
            mtu: self.mtu,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.medium = Medium::Ip;
        cap.max_transmission_unit = self.mtu;
        cap.max_burst_size = Some(self.slots);
        cap
    }
}
