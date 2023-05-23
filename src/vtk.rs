use core::str;
use std::{io::{Error, Write, Read}, net::TcpStream, collections::HashMap, time::{Duration, Instant}};

use ignore_result::Ignore;
use num_derive::FromPrimitive;

const VTK_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(PartialEq, Hash, Eq, FromPrimitive, Debug, Clone, Copy)]
#[repr(u8)]
pub enum TlvKey {
    MsgName = 0x01,
    OperationNum = 0x03,
    AmountInMinorCurrencyUnit = 0x04,
    KeepaliveIntervalInSecs = 0x05,
    OperationTimeoutInSecs = 0x06,
    EventName = 0x07,
    EventNum = 0x08,
    ProductId = 0x09,
    QrCodeData = 0x0A,
    TcpIpDestantion = 0x0B,
    OutgoingByteCounter = 0x0C,
    SimpleDataBlock = 0x0D,
    ConfirmableDataBlock = 0x0E,
    ProductName = 0x0F,
    PosManagementData = 0x10,
    LocalTime = 0x11,
    SysInfo = 0x12,
    BankingReceipt = 0x13,
    DisplayTimeInMs = 0x14,
}

#[derive(Clone)]
pub struct Tlv {
    data: HashMap<TlvKey, Vec<u8>>,
}

impl Tlv {
    pub fn new() -> Self {
        Self {data: HashMap::new()}
    }

    fn deser_one(raw: &Vec<u8>, begin: usize) -> Option<(u8, Vec<u8>, usize)> {
        if raw.len() - begin < 2 {return None;}
        let k = raw[begin];
        let len = raw[begin+1] as usize;
        if (begin + len + 2) > raw.len() {return None;}
        let v = raw[begin+2..begin+len+2].to_vec();
        Some((k, v, len + 2))
    }

    pub fn deserialize(raw: &Vec<u8>) -> Self {
        let mut data = HashMap::new();
        let mut i = 0;
        loop {
            match Self::deser_one(raw, i) {
                Some((k, v, len)) => {
                    match num::FromPrimitive::from_u8(k) {
                        Some(k) => {data.insert(k, v);},
                        None => (),
                    }
                    i += len;
                },
                None => break,
            }
        }
        Self {data: data}
    }

    pub fn serialize(self) -> Vec<u8> {
        let mut output = Vec::new();
        for (k, v) in self.data {
            output.push(k as u8);
            let len = v.len() as u8;
            output.push(len);
            for b in v {
                output.push(b);
            }
        }
        output
    }

    pub fn data<'a>(&'a self) -> &'a HashMap<TlvKey, Vec<u8>> {
        &self.data
    }

    pub fn get_bin(&self, key: TlvKey) -> Option<&Vec<u8>> {
        self.data.get(&key)
    }

    pub fn set_bin(&mut self, key: TlvKey, data: &[u8]) {
        self.data.insert(key, data.to_vec());
    }

    pub fn set_str(&mut self, key: TlvKey, data: &str) {
        self.data.insert(key, data.as_bytes().to_vec());
    }
}

pub struct Vtk {
    ip: String,
    port: u16,
    tcp: Option<TcpStream>,
}

impl Vtk {
    pub fn new(ip: &str, port: u16) -> Result<Self, Error> {
        let s = Self {
            ip: String::from(ip),
            port: port,
            tcp: None,
        };
        Ok(s)
    }

    pub fn is_connected(&self) -> bool {
        self.tcp.is_some()
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        if self.tcp.is_none() {
            self.tcp = Some(TcpStream::connect(format!("{}:{}", self.ip, self.port))?);
            self.tcp.as_mut().unwrap().set_write_timeout(Some(VTK_WRITE_TIMEOUT))?;
        }
        Ok(())
    }

    pub fn disconnect(&mut self) {
        match self.tcp.take() {
            Some(tcp) => {
                tcp.shutdown(std::net::Shutdown::Both).ignore();
            },
            None => ()
        }
    }

    pub fn idle(&mut self, add: Option<Tlv>) -> Result<(), Error> {
        self.disconnect();
        let tlv = match add {
            Some(tlv) => tlv,
            None => Tlv::new(),
        };
        self.send("IDL", tlv)?;
        _ = self.receive(2000)?;
        self.disconnect();
        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), Error> {
        self.disconnect();
        self.send("DIS", Tlv::new())?;
        _ = self.receive(2000)?;
        Ok(())
    }

    pub fn show_qr(&mut self, qr: &str) -> Result<(), Error> {
        let mut tlv = Tlv::new();
        tlv.set_str(TlvKey::QrCodeData, qr);
        self.idle(Some(tlv))
    }

    pub fn send(&mut self, msg_name: &str, mut tlv: Tlv) -> Result<(), Error> {
        tlv.set_str(TlvKey::MsgName, msg_name);
        let mut tlv = tlv.serialize();
        let mut buf = Vec::new();
        let len = (tlv.len() + 2) as u16;
        let len_buf: [u8;2] = len.to_be_bytes();
        buf.push(len_buf[0]);
        buf.push(len_buf[1]);
        buf.push(0x96);
        buf.push(0xFB);
        buf.append(&mut tlv);
        self.connect()?;
        self.tcp.as_mut().unwrap().write_all(&buf)
    }

    pub fn receive(&mut self, timeout_ms: u64) -> Result<Tlv, Error> {
        let mut buf: [u8;512] = [0;512];
        self.connect()?;
        self.tcp.as_mut().unwrap().set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let size = self.tcp.as_mut().unwrap().read(&mut buf)?;
        if size < 9 {
            return Err(Error::new(std::io::ErrorKind::Other, "too few bytes received"));
        }
        Ok(Tlv::deserialize(&buf[4..].to_vec()))
    }

}

impl Drop for Vtk {
    fn drop(&mut self) {
        self.disconnect();
    }
}
