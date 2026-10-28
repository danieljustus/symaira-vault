//! Regression tests for the bounded restore entry-limit pre-pass (#1483).
use super::*;
use std::{cell::Cell, rc::Rc};

/// A tar stream of one `declared`-byte member whose body is zeros, counting
/// every byte handed to the consumer.
struct CountingTar {
    header: Vec<u8>,
    body_left: u64,
    sent: Rc<Cell<u64>>,
}

impl CountingTar {
    fn new(declared: u64, sent: Rc<Cell<u64>>) -> Self {
        let mut header = Header::new_gnu();
        header.set_path("entries/huge").unwrap();
        header.set_size(declared);
        header.set_mode(0o600);
        header.set_cksum();
        Self {
            header: header.as_bytes().to_vec(),
            body_left: declared,
            sent,
        }
    }
}

impl Read for CountingTar {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = if self.header.is_empty() {
            let count = buffer
                .len()
                .min(usize::try_from(self.body_left).unwrap_or(usize::MAX));
            buffer[..count].fill(0);
            self.body_left -= count as u64;
            count
        } else {
            let count = buffer.len().min(self.header.len());
            buffer[..count].copy_from_slice(&self.header[..count]);
            self.header.drain(..count);
            count
        };
        self.sent.set(self.sent.get() + count as u64);
        Ok(count)
    }
}

#[test]
fn oversized_member_body_is_not_inflated() {
    let declared = 64 << 20;
    let sent = Rc::new(Cell::new(0));
    scan_entry_limit(CountingTar::new(declared, sent.clone()), 1 << 10, u64::MAX).unwrap();
    assert!(
        sent.get() < 64 << 10,
        "pre-pass consumed {} bytes of a {declared}-byte member",
        sent.get()
    );
}

#[test]
fn body_past_the_total_budget_is_not_inflated() {
    let declared = 64 << 20;
    let sent = Rc::new(Cell::new(0));
    scan_entry_limit(CountingTar::new(declared, sent.clone()), u64::MAX, 1 << 10).unwrap();
    assert!(sent.get() < 64 << 10, "consumed {}", sent.get());
}

#[test]
fn member_within_the_limits_is_still_skipped_to_the_next_header() {
    // Negative control: the bound must not stop the scan for members that
    // pass the size checks (the whole body is read to reach the trailer).
    let declared = 1 << 20;
    let sent = Rc::new(Cell::new(0));
    scan_entry_limit(CountingTar::new(declared, sent.clone()), 2 << 20, u64::MAX).unwrap();
    assert!(sent.get() >= declared, "consumed {}", sent.get());
}
