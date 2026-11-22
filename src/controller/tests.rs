//! Tests of the link layer task's handling of the advertising settings.

use super::*;
use crate::pdu::Peer;

#[test]
fn the_task_s_copy_of_the_resolving_list_is_overwritten_after_its_pass() {
    let mut current = Some(Settings::new());
    if let Some(settings) = current.as_mut() {
        assert!(settings.resolving.add_keys(Peer::new([1, 2, 3, 4, 5, 6], false), [0x11; 16], [0x22; 16]));
    }
    let Some(settings) = current.as_mut().map(Taken) else { return };
    // The pass reads the keys through it.
    assert_eq!(settings.resolving.local_key(None), Some([0x22; 16]));
    drop(settings);
    assert!(current.is_some_and(|left| left.resolving.is_empty()));
}
