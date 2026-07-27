//! Blocking-I/O adapters, direct ports of rustls' `Stream`/`StreamOwned`.
//!
//! They bridge the sans-I/O [`ConnectionCommon`] to a real socket implementing `Read + Write`, so a
//! caller can treat the connection as an ordinary byte stream. They pump only the application-data
//! channel; inbound control is still handled automatically by `process_new_packets` (which these
//! adapters call), and rekey initiation stays the caller's responsibility.

use std::io::{self, Read, Write};
use std::ops::DerefMut;

use crate::conn::ConnectionCommon;
use crate::error::Error;

fn io_err(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// A borrowed `{ connection, socket }` pair implementing `Read`/`Write`.
pub struct Stream<'a, C, T> {
    pub conn: &'a mut C,
    pub sock: &'a mut T,
}

impl<'a, C, T> Stream<'a, C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    pub fn new(conn: &'a mut C, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }

    fn flush_output(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            let n = self.conn.write_tls(self.sock)?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Flush pending output and, if still in the initial handshake, pump the socket until it
    /// completes. Called before application reads/writes.
    fn complete_io(&mut self) -> io::Result<()> {
        self.flush_output()?;
        while self.conn.is_handshaking() {
            let n = self.conn.read_tls(self.sock)?;
            self.conn.process_new_packets().map_err(io_err)?;
            self.flush_output()?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ));
            }
        }
        Ok(())
    }
}

impl<C, T> Read for Stream<'_, C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_io()?;
        // Pull + process TLS until plaintext is available (wants_read() flips false) or EOF.
        while self.conn.wants_read() {
            let n = self.conn.read_tls(self.sock)?;
            self.conn.process_new_packets().map_err(io_err)?;
            self.flush_output()?; // processing may have queued control replies
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before application data was available",
                ));
            }
        }
        self.conn.reader().read(buf)
    }
}

impl<C, T> Write for Stream<'_, C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_io()?;
        let n = self.conn.writer().write(buf)?;
        self.flush_output()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_output()?;
        self.sock.flush()
    }
}

/// An owned `{ connection, socket }` pair implementing `Read`/`Write`.
pub struct StreamOwned<C, T> {
    pub conn: C,
    pub sock: T,
}

impl<C, T> StreamOwned<C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    pub fn new(conn: C, sock: T) -> Self {
        Self { conn, sock }
    }

    /// Borrow as a [`Stream`].
    pub fn as_stream(&mut self) -> Stream<'_, C, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T> Read for StreamOwned<C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, T> Write for StreamOwned<C, T>
where
    C: DerefMut<Target = ConnectionCommon>,
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.as_stream().flush()
    }
}
