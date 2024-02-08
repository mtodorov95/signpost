type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer { buf: [0;512], pos: 0 }
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

            // Jump to another offset
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.set_position(pos+2)?;
                }

                let b2 = self.peek(pos+1)? as u16;
                let offset = (((len as u16) ^ 0xC0)) << 8 | b2;
                pos = offset as usize;

                jumped = true;
                curr_jump+=1;
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

    fn peek(&self, pos:usize) -> Result<u8> {
       if pos >= self.buf.len() {
            return Err("end of buffer".into());
       } 
       Ok(self.buf[pos])
    }

    fn peek_many(&self, start: usize, len: usize) -> Result<&[u8]> {
       if start+len >= self.buf.len() {
            return Err("end of buffer".into());
       } 
       Ok(&self.buf[start..start+len as usize])
    }

    fn end_of_buf(&self) -> bool {
        self.pos >= self.buf.len()
    }
}
