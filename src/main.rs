// Copyright 2016 Daniel Harrison. All Rights Reserved.

extern crate byteorder;
extern crate memmap;

use byteorder::{BigEndian, ByteOrder};
use memmap::{Mmap, Protection};

// const DATA_MAGIC: &'static str = "DATABLK*";
const INDEX_MAGIC: &'static str = "IDXBLK)+";
const TRAILER_MAGIC: &'static str = "TRABLK\"$";

const COMPRESSION_NONE: u32 = 2;
// const COMPRESSION_SNAPPY: u32 = 3;

#[derive(Debug)]
struct Trailer {
    offset: usize,

    major_version: u32,
    minor_version: u32,

    file_info_offset: usize,
    data_index_offset: usize,
    data_index_count: u32,
    meta_index_offset: usize,
    meta_index_count: u32,
    total_uncompressed_data_bytes: u64,
    entry_count: u32,
    compression_codec: u32,
}

impl Trailer {
    pub fn parse(buf: &[u8]) -> Trailer {
        let v = BigEndian::read_u32(&buf[buf.len()-4..]);
        let major_version = v & 0x00ffffffu32;
        let minor_version = v >> 24;
        if major_version != 1 || minor_version != 0 {
            panic!("unsupported version");
        }

        let trailer_buf = &buf[buf.len()-60..];
        if &trailer_buf[..8] != TRAILER_MAGIC.as_bytes() {
            panic!("bad trailer magic")
        }

        return Trailer{
            offset: buf.len()-60 as usize,

            major_version: major_version,
            minor_version: minor_version,

            file_info_offset: BigEndian::read_u64(&trailer_buf[8..16]) as usize,
            data_index_offset: BigEndian::read_u64(&trailer_buf[16..24]) as usize,
            data_index_count: BigEndian::read_u32(&trailer_buf[24..28]),
            meta_index_offset: BigEndian::read_u64(&trailer_buf[28..36]) as usize,
            meta_index_count: BigEndian::read_u32(&trailer_buf[36..40]),
            total_uncompressed_data_bytes: BigEndian::read_u64(&trailer_buf[40..48]),
            entry_count: BigEndian::read_u32(&trailer_buf[48..52]),
            compression_codec: BigEndian::read_u32(&trailer_buf[52..56]),
        };
    }
}

#[derive(Debug)]
struct Block<'a> {
    offset: usize,
    size: usize,
    first_key_bytes: &'a[u8],
}

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    trailer: Trailer,
    index: Vec<Block<'a>>,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &[u8]) -> Reader {
        let t = Trailer::parse(buf);

        if t.compression_codec != COMPRESSION_NONE {
            panic!("unsupported compression");
        }

        let data_index_end = if t.meta_index_offset != 0 {
            t.meta_index_offset
        } else {
            t.offset
        };


        let index_buf = &buf[t.data_index_offset..data_index_end];
        if &index_buf[..8] != INDEX_MAGIC.as_bytes() {
            panic!("bad index magic");
        }

        let mut index: Vec<Block> = Vec::with_capacity(t.data_index_count as usize);
        let mut i: usize = 8;
        for _ in 0..t.data_index_count {
            let offset = BigEndian::read_u64(&index_buf[i..i+8]) as usize;
            i += 8;
            let size = BigEndian::read_u32(&index_buf[i..i+4]) as usize;
            i += 4;

            let (first_key_len, s) = uvarint(&index_buf[i..]);
            let first_key_len = first_key_len as usize;
            i += s;
            let first_key_bytes = &index_buf[i..i+first_key_len];
            i += first_key_len;

            index.push(Block{
                offset: offset,
                size: size,
                first_key_bytes: first_key_bytes,
            })
        }

        return Reader{buf: buf, trailer: t, index: index};
    }

    fn find_block(&self, from_idx: usize, key: &[u8]) -> Option<usize> {
        // TODO(dan): Do this with binary search.
        let mut idx = from_idx;
        for i in from_idx..self.index.len() {
            // println!("block: {:?} {:?} key {:?}", i, self.index[i].first_key_bytes, key);
            if self.index[i].first_key_bytes.gt(key) {
                // println!("found block {:?}", i);
                return Some(idx);
            }
            idx = i;
        }
        return None;
    }

    fn get_block_data(&self, block_idx: usize) -> &'a [u8] {
        let block = &self.index[block_idx];
        return &self.buf[block.offset..block.offset+block.size];
    }
}

pub struct Scanner<'a> {
    reader: Reader<'a>,
    block_idx: usize,
    block_data: Option<&'a[u8]>,
    pos: usize,
}

impl<'a> Scanner<'a> {
    pub fn reset(&mut self) {
        self.block_idx = 0;
        // self.blockData = nil
        self.pos = 0;
    }

    fn block_for(&mut self, key: &[u8]) -> Option<&[u8]> {
        if self.reader.index[self.block_idx].first_key_bytes.gt(key) {
            return None;
        }

        let idx = match self.reader.find_block(self.block_idx, key) {
            Some(idx) => idx,
            None => return None,
        };

        if idx != self.block_idx || self.block_data.is_none() {
            println!("loading block {:?}", idx);
            // Need to load a new block.
            let block_data = self.reader.get_block_data(idx);
            self.pos = 8;
            self.block_idx = idx;
            self.block_data = Some(block_data);
        }

        return self.block_data;
    }

    pub fn get_first(&mut self, key: &[u8]) -> Option<&[u8]> {
        let block_data = match self.block_for(key) {
            Some(block_data) => {
                // println!("searching block {:?}", block_data.len());
                block_data
            },
            None => return None,
        };

        // TODO(dan): Stop pattern matching the borrow checker and learn what's going on.
        // let mut buf = &block_data[self.pos..];
        let mut buf = &block_data[8..];
        loop {
            if buf.len() < 8 {
                break;
            }
            let key_len = BigEndian::read_u32(&buf[0..4]) as usize;
            let val_len = BigEndian::read_u32(&buf[4..8]) as usize;
            buf = &buf[8..];
            let key_buf = &buf[..key_len];
            // println!("key {:?} {:?}", key_buf, key);
            let val_buf = &buf[key_len..key_len+val_len];
            buf = &buf[key_len+val_len..];
            if key_buf == key {
                return Some(val_buf);
            } else if key_buf.gt(key) {
                break;
            }
        }
        return None;
    }
}

fn main() {
    let file_mmap = Mmap::open_path("data.hfile", Protection::Read).unwrap();
    let bytes: &[u8] = unsafe { file_mmap.as_slice() };
    let reader = Reader::new(bytes);
    // println!("The bytes: {:?}", reader);
    let mut scanner = Scanner{reader: reader, block_data: None, block_idx: 0, pos: 0};

    {
        scanner.reset();
        let key = &[0u8, 0, 16, 211];
        let value = scanner.get_first(key);
        println!("The bytes: {:?} {:?}", key, value);
    }

    let key = &[0u8, 0, 15, 211];
    println!("The bytes: {:?} {:?}", key, scanner.get_first(key));
    scanner.reset();
    println!("The bytes: {:?} {:?}", key, scanner.get_first(key));
}

// TODO(dan): Haha, jk, this is not the real varint.
fn uvarint(buf: &[u8]) -> (u64, usize) {
    let mut x: u64 = 0;
    let mut s: u64 = 0;
    let mut i: usize = 0;
    for b in buf {
        i += 1;
        if *b < 0x80u8 {
            x = x | (*b as u64) << s;
            break;
        }
        x |= (*b as u64) & 0x7f << s;
        s += 7;
    }
    return (x, i);
}
