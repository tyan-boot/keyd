#![cfg(unix)]

use std::os::unix::net::{UnixStream, UnixListener};
use std::os::raw;
use std::io::Read;
use std::io::Write;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    let sock = &args[1];

    std::fs::remove_file("/tmp/test-keyd-proxy.sock").ok();
    let listener = UnixListener::bind("/tmp/test-keyd-proxy.sock").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 4096];

                let target = UnixStream::connect(sock);

                match target {
                    Ok(mut target) => {
                        loop {
                            let r = stream.read(&mut buf).unwrap();

                            dbg!(&buf[0..r]);
                            target.write_all(&buf[0..r]).unwrap();


                            let r = target.read(&mut buf).unwrap();
                            dbg!(&buf[0..r]);
                            stream.write_all(&buf[0..r]).unwrap();
                        }

                    },
                    Err(e) => {
                        dbg!(e);
                    }
                }
            },
            Err(e) => {
                dbg!(e);
            }
        }
    }

}