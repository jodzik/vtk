mod vtk;

use std::{thread, time::Duration};

use crate::vtk::{Tlv, TlvKey};

fn main() {
    let mut dev = vtk::Vtk::new("192.168.0.12", 62801).unwrap();
    let mut tlv = Tlv::new();
    tlv.set_str(TlvKey::QrCodeData, "data");
    let mut i = 0;
    loop {
        if i % 10 == 0 {
            dev.show_qr("1234567890abcdeABCDEqr").unwrap();
        } else {
            dev.disable().unwrap();
        }

        thread::sleep(Duration::from_secs(10));
        i += 1;
    }
}
