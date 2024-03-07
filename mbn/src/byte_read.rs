use crate::error::ParseError;

pub(crate) trait ByteRead: Sized {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)>;
}

#[derive(Clone)]
pub(crate) struct ByteReader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buffer: &'a [u8]) -> ByteReader<'a> {
        Self { buffer, offset: 0 }
    }

    pub fn current(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }

    pub fn available(&self) -> usize {
        self.buffer.len() - self.offset
    }

    pub fn peek<T: ByteRead>(&self, offset: usize) -> crate::Result<T> {
        let mut reader = self.clone();
        reader.skip(offset)?;
        T::read(&reader).map(|(t, _)| t)
    }

    pub fn read<T: ByteRead>(&mut self) -> crate::Result<T> {
        let (t, count) = T::read(self)?;
        self.offset += count;
        Ok(t)
    }

    pub fn skip(&mut self, count: usize) -> crate::Result<Vec<u8>> {
        if self.offset + count > self.buffer.len() {
            Err(ParseError::InputUnexpectedTermination)
        } else {
            let v = self.buffer[self.offset..self.offset + count].to_vec();
            self.offset += count;
            Ok(v)
        }
    }
}

impl ByteRead for u8 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            *(buffer
                .current()
                .first()
                .ok_or(ParseError::InputUnexpectedTermination)?),
            1,
        ))
    }
}

impl ByteRead for u32 {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            u32::from_le_bytes(
                buffer
                    .current()
                    .get(0..std::mem::size_of::<Self>())
                    .ok_or(ParseError::InputUnexpectedTermination)?
                    .try_into()
                    .unwrap(),
            ),
            std::mem::size_of::<Self>(),
        ))
    }
}

impl<const N: usize> ByteRead for [u8; N] {
    fn read(buffer: &ByteReader<'_>) -> crate::Result<(Self, usize)> {
        Ok((
            buffer
                .current()
                .get(0..std::mem::size_of::<Self>())
                .ok_or(ParseError::InputUnexpectedTermination)?
                .try_into()
                .unwrap(),
            N,
        ))
    }
}
