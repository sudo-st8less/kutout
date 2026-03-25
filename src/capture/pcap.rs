// pcap writer

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const LINKTYPE_ETHERNET: u32 = 1;
const DEFAULT_SNAPLEN: u32 = 65535;

// "knowing is not enough; we must apply." — tao te ching, 47 (loosely)

pub struct PcapWriter {
    writer: BufWriter<File>,
    packet_count: u64,
}

impl PcapWriter {
    // create file, write global header
    pub fn create(path: &Path) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("failed to create pcap: {}", path.display()))?;
        let mut writer = BufWriter::new(file);

        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&DEFAULT_SNAPLEN.to_le_bytes())?;
        writer.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        writer.flush()?;

        Ok(Self {
            writer,
            packet_count: 0,
        })
    }

    // write packet record
    pub fn write_packet(&mut self, data: &[u8], timestamp_us: u64) -> Result<()> {
        let ts_sec = (timestamp_us / 1_000_000) as u32;
        let ts_usec = (timestamp_us % 1_000_000) as u32;
        let len = data.len() as u32;

        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;

        self.writer.write_all(data)?;
        self.packet_count += 1;

        if self.packet_count.is_multiple_of(100) {
            self.writer.flush()?;
        }

        Ok(())
    }

    // flush, return count
    pub fn finish(mut self) -> Result<u64> {
        self.writer.flush()?;
        Ok(self.packet_count)
    }

    #[allow(dead_code)]
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_pcap_write_and_read_back() {
        let path = Path::new("/tmp/kutout_test.pcap");

        {
            let mut writer = PcapWriter::create(path).unwrap();
            writer
                .write_packet(&[0xff; 64], 1_000_000)
                .unwrap();
            writer
                .write_packet(&[0xaa; 128], 2_000_000)
                .unwrap();
            let count = writer.finish().unwrap();
            assert_eq!(count, 2);
        }

        let data = fs::read(path).unwrap();

        assert!(data.len() >= 24);

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        let linktype = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        assert_eq!(linktype, LINKTYPE_ETHERNET);

        let ts_sec = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        assert_eq!(ts_sec, 1);
        let cap_len = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        assert_eq!(cap_len, 64);

        // 24 + 16+64 + 16+128 = 248
        assert_eq!(data.len(), 248);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_pcap_empty() {
        let path = Path::new("/tmp/kutout_test_empty.pcap");
        let writer = PcapWriter::create(path).unwrap();
        let count = writer.finish().unwrap();
        assert_eq!(count, 0);

        let data = fs::read(path).unwrap();
        assert_eq!(data.len(), 24);

        let _ = fs::remove_file(path);
    }
}
