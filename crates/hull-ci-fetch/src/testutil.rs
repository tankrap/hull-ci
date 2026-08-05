//! Hand-built tar archives for the tests, including ones no well-behaved writer will produce.
//!
//! The header fields are written **directly** rather than through `Builder::append_path`, because
//! the convenience helpers validate their input — and the entries we most need to test (`/etc/x`,
//! `../../escape`, a fifo, a setuid bit) are exactly the ones a well-behaved writer refuses to emit.
//! Testing an extractor against only the archives a friendly library will write tests nothing.

use tar::{EntryType, Header};

#[derive(Debug, Clone)]
pub struct TarEntry {
    pub path: String,
    pub kind: EntryType,
    pub mode: u32,
    pub data: Vec<u8>,
    pub link: Option<String>,
}

impl TarEntry {
    pub fn file(path: &str, data: &[u8]) -> Self {
        TarEntry { path: path.into(), kind: EntryType::Regular, mode: 0o644, data: data.to_vec(), link: None }
    }

    pub fn dir(path: &str) -> Self {
        TarEntry { path: path.into(), kind: EntryType::Directory, mode: 0o755, data: Vec::new(), link: None }
    }

    pub fn symlink(path: &str, target: &str) -> Self {
        TarEntry {
            path: path.into(),
            kind: EntryType::Symlink,
            mode: 0o777,
            data: Vec::new(),
            link: Some(target.into()),
        }
    }

    pub fn hardlink(path: &str, target: &str) -> Self {
        TarEntry { path: path.into(), kind: EntryType::Link, mode: 0o644, data: Vec::new(), link: Some(target.into()) }
    }

    pub fn special(path: &str, kind: EntryType) -> Self {
        TarEntry { path: path.into(), kind, mode: 0o644, data: Vec::new(), link: None }
    }

    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

/// Serialize entries into a tar archive, bypassing every convenience check.
pub fn tar_bytes(entries: &[TarEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        for e in entries {
            let mut header = Header::new_gnu();
            header.set_size(e.data.len() as u64);
            header.set_mode(e.mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(e.kind);
            set_field(header_name(&mut header), e.path.as_bytes());
            if let Some(link) = &e.link {
                set_field(header_linkname(&mut header), link.as_bytes());
            }
            header.set_cksum();
            builder.append(&header, e.data.as_slice()).expect("write tar entry");
        }
        builder.finish().expect("finish tar");
    }
    out
}

fn header_name(h: &mut Header) -> &mut [u8; 100] {
    &mut h.as_gnu_mut().expect("gnu header").name
}

fn header_linkname(h: &mut Header) -> &mut [u8; 100] {
    &mut h.as_gnu_mut().expect("gnu header").linkname
}

fn set_field(field: &mut [u8; 100], value: &[u8]) {
    assert!(value.len() < field.len(), "test paths stay short enough for the fixed header field");
    field.fill(0);
    field[..value.len()].copy_from_slice(value);
}
