use std::net::{Ipv4Addr, Ipv6Addr};

type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub resources: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn new() -> Self {
        DNSPacket {
            header: DNSHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = DNSPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DNSQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DNSRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DNSRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DNSRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum DNSRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DNSRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((addr >> 24) & 0xFF) as u8,
                    ((addr >> 16) & 0xFF) as u8,
                    ((addr >> 8) & 0xFF) as u8,
                    ((addr >> 0) & 0xFF) as u8,
                );

                Ok(DNSRecord::A { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DNSRecord::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DNSRecord::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DNSRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::AAAA => {
                let addr1 = buffer.read_u32()?;
                let addr2 = buffer.read_u32()?;
                let addr3 = buffer.read_u32()?;
                let addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((addr1 >> 16) & 0xFFFF) as u16,
                    ((addr1 >> 0) & 0xFFFF) as u16,
                    ((addr2 >> 16) & 0xFFFF) as u16,
                    ((addr2 >> 0) & 0xFFFF) as u16,
                    ((addr3 >> 16) & 0xFFFF) as u16,
                    ((addr3 >> 0) & 0xFFFF) as u16,
                    ((addr4 >> 16) & 0xFFFF) as u16,
                    ((addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DNSRecord::AAAA { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.skip(data_len as usize)?;

                Ok(DNSRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos;

        match *self {
            DNSRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DNSRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos;
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;
                let size = buffer.pos - (pos + 2);
                buffer.set_u16_at(pos, size as u16)?;
            }
            DNSRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos;
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;
                let size = buffer.pos - (pos + 2);
                buffer.set_u16_at(pos, size as u16)?;
            }
            DNSRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos;
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;
                let size = buffer.pos - (pos + 2);
                buffer.set_u16_at(pos, size as u16)?;
            }
            DNSRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DNSRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos - start_pos)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug)]
pub struct DNSQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DNSQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        DNSQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        // Class
        let _ = buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        let qtype = self.qtype.to_num();
        buffer.write_u16(qtype)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct DNSHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,
    pub rescode: ResultCode,
    pub cheching_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DNSHeader {
    pub fn new() -> DNSHeader {
        DNSHeader {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            cheching_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.cheching_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

impl DNSHeader {
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.cheching_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn read_qname(&mut self, out: &mut String) -> Result<()> {
        let mut pos = self.pos;
        let mut jumped = false;
        // Prevent cycles
        let max_jumps = 5;
        let mut curr_jump = 0;

        let mut delimiter = "";

        loop {
            if curr_jump > max_jumps {
                return Err(format!("Exceeded jump limit of {}", max_jumps).into());
            }

            // Get length of label
            let len = self.peek(pos)?;

            // Most significant two bits set
            // Jump to another offset
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.set_position(pos + 2)?;
                }

                let b2 = self.peek(pos + 1)? as u16;
                let offset = ((len as u16) ^ 0xC0) << 8 | b2;
                pos = offset as usize;

                jumped = true;
                curr_jump += 1;
                continue;
            } else {
                // Read label

                // Skip the length
                pos += 1;

                // End of domain name
                if len == 0 {
                    break;
                }

                out.push_str(delimiter);
                let str_buf = self.peek_many(pos, len as usize)?;
                out.push_str(&String::from_utf8_lossy(str_buf).to_lowercase());
                delimiter = ".";
                pos += len as usize;
            }
        }

        if !jumped {
            self.set_position(pos)?;
        }
        Ok(())
    }

    fn skip(&mut self, amount: usize) -> Result<()> {
        self.pos += amount;
        Ok(())
    }

    fn set_position(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and increment the position by one
    fn read_u8(&mut self) -> Result<u8> {
        if self.end_of_buf() {
            return Err("end of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Read two bytes and increment the position by two
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16);
        Ok(res)
    }

    /// Read four bytes and increment the position by four
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | (self.read_u8()? as u32);
        Ok(res)
    }

    fn peek(&self, pos: usize) -> Result<u8> {
        if pos >= self.buf.len() {
            return Err("end of buffer".into());
        }
        Ok(self.buf[pos])
    }

    pub fn peek_many(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= self.buf.len() {
            return Err("end of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn end_of_buf(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

impl BytePacketBuffer {
    fn set_u8_at(&mut self, pos: usize, value: u8) -> Result<()> {
        if pos > self.buf.len() {
            return Err("end of buffer".into());
        }
        self.buf[pos] = value;

        Ok(())
    }

    fn set_u16_at(&mut self, pos: usize, value: u16) -> Result<()> {
        self.set_u8_at(pos, (value >> 8) as u8)?;
        self.set_u8_at(pos + 1, (value & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a single byte to the buffer and increment
    /// the position by one.
    fn write(&mut self, value: u8) -> Result<()> {
        if self.end_of_buf() {
            return Err("end of buffer".into());
        }

        self.buf[self.pos] = value;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write(value)?;
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<()> {
        self.write((value >> 8) as u8)?;
        self.write((value & 0xFF) as u8)?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write(((value >> 24) & 0xFF) as u8)?;
        self.write(((value >> 16) & 0xFF) as u8)?;
        self.write(((value >> 8) & 0xFF) as u8)?;
        self.write(((value >> 0) & 0xFF) as u8)?;
        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split(".") {
            let len = label.len();
            if len > 0x3f {
                return Err("label exceeds 63 characters".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}
