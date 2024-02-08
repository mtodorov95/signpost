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
