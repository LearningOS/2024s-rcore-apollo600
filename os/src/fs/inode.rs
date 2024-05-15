//! `Arc<Inode>` -> `OSInodeInner`: In order to open files concurrently
//! we need to wrap `Inode` into `Arc`,but `Mutex` in `Inode` prevents
//! file systems from being accessed simultaneously
//!
//! `UPSafeCell<OSInodeInner>` -> `OSInode`: for static `ROOT_INODE`,we
//! need to wrap `OSInodeInner` into `UPSafeCell`
use super::{File, StatMode};
use crate::drivers::BLOCK_DEVICE;
use crate::mm::UserBuffer;
use crate::sync::UPSafeCell;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use easy_fs::{EasyFileSystem, Inode};
use lazy_static::*;
use alloc::string::String;

/// inode in memory
/// A wrapper around a filesystem inode
/// to implement File trait atop
pub struct OSInode {
    readable: bool,
    writable: bool,
    path: String,
    inner: UPSafeCell<OSInodeInner>,
}
/// The OS inode inner in 'UPSafeCell'
pub struct OSInodeInner {
    offset: usize,
    inode: Arc<Inode>,
}

impl OSInode {
    /// create a new inode in memory
    pub fn new(readable: bool, writable: bool, path: &str, inode: Arc<Inode>) -> Self {
        Self {
            readable,
            writable,
            path: path.into(),
            inner: unsafe { UPSafeCell::new(OSInodeInner { offset: 0, inode }) },
        }
    }
    /// read all data from the inode
    pub fn read_all(&self) -> Vec<u8> {
        let mut inner = self.inner.exclusive_access();
        let mut buffer = [0u8; 512];
        let mut v: Vec<u8> = Vec::new();
        loop {
            let len = inner.inode.read_at(inner.offset, &mut buffer);
            if len == 0 {
                break;
            }
            inner.offset += len;
            v.extend_from_slice(&buffer[..len]);
        }
        v
    }
}

lazy_static! {
    pub static ref ROOT_INODE: Arc<Inode> = {
        let efs = EasyFileSystem::open(BLOCK_DEVICE.clone());
        Arc::new(EasyFileSystem::root_inode(&efs))
    };
}

/// List all apps in the root directory
pub fn list_apps() {
    println!("/**** APPS ****");
    for app in ROOT_INODE.ls() {
        println!("{}", app);
    }
    println!("**************/");
}

/// find inode_id by file name
pub fn get_ino(file_name: &str) -> u32 {
    ROOT_INODE.read_disk_inode(|disk_inode| {
        ROOT_INODE.find_inode_id(file_name, disk_inode).unwrap()
    })
}

/// link a new path to a existed path
pub fn link(link_name: &str, file_name: &str) {
    let src_inode_id = ROOT_INODE.read_disk_inode(|disk_inode| {
        ROOT_INODE.find_inode_id(file_name, disk_inode).unwrap()
    });
    ROOT_INODE.map(link_name, src_inode_id);

    let src_inode = ROOT_INODE.find(link_name).unwrap();
    src_inode.inc_link();
}

/// delete a link
pub fn unlink(link_name: &str) -> isize {
    let inode = ROOT_INODE.find(link_name).unwrap();
    inode.dec_link();

    if get_nlink(link_name) == 0 {
        inode.clear();
    }

    ROOT_INODE.unmap(link_name);
    0
}

/// check if a file exist
pub fn get_file_type(path: &str) -> StatMode {
    let inode = ROOT_INODE.find(path);
    if inode.is_none() {
        return StatMode::NULL;
    }
    let inode = inode.unwrap();
    inode.read_disk_inode(|disk_inode| {
        if disk_inode.is_dir() {
            StatMode::DIR
        } else if disk_inode.is_file() {
            StatMode::FILE
        } else {
            StatMode::NULL
        }
    })
}

/// get nlink by path
pub fn get_nlink(path: &str) -> u32 {
    let inode = ROOT_INODE.find(path);
    if inode.is_none() {
        return 0;
    }
    let inode = inode.unwrap();
    inode.read_disk_inode(|disk_inode| {
        disk_inode.nlink
    })
}

bitflags! {
    ///  The flags argument to the open() system call is constructed by ORing together zero or more of the following values:
    pub struct OpenFlags: u32 {
        /// readyonly
        const RDONLY = 0;
        /// writeonly
        const WRONLY = 1 << 0;
        /// read and write
        const RDWR = 1 << 1;
        /// create new file
        const CREATE = 1 << 9;
        /// truncate file size to 0
        const TRUNC = 1 << 10;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

/// Open a file
pub fn open_file(name: &str, flags: OpenFlags) -> Option<Arc<OSInode>> {
    let (readable, writable) = flags.read_write();
    if flags.contains(OpenFlags::CREATE) {
        if let Some(inode) = ROOT_INODE.find(name) {
            // clear size
            inode.clear();
            Some(Arc::new(OSInode::new(readable, writable, name, inode)))
        } else {
            // create file
            ROOT_INODE
                .create(name)
                .map(|inode| {
                    inode.inc_link();
                    Arc::new(OSInode::new(readable, writable, name, inode))
                })
        }
    } else {
        ROOT_INODE.find(name).map(|inode| {
            if flags.contains(OpenFlags::TRUNC) {
                inode.clear();
            }
            Arc::new(OSInode::new(readable, writable, name, inode))
        })
    }
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.exclusive_access();
        let mut total_read_size = 0usize;
        for slice in buf.buffers.iter_mut() {
            let read_size = inner.inode.read_at(inner.offset, *slice);
            if read_size == 0 {
                break;
            }
            inner.offset += read_size;
            total_read_size += read_size;
        }
        total_read_size
    }
    fn write(&self, buf: UserBuffer) -> usize {
        let mut inner = self.inner.exclusive_access();
        let mut total_write_size = 0usize;
        for slice in buf.buffers.iter() {
            let write_size = inner.inode.write_at(inner.offset, *slice);
            assert_eq!(write_size, slice.len());
            inner.offset += write_size;
            total_write_size += write_size;
        }
        total_write_size
    }
    fn get_path(&self) -> &str {
        &self.path
    }
}
