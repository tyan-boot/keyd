#![cfg(unix)]

use std::os::unix::net::UnixListener;

use std::io::Read;
use std::io::Write;
// use keyd::parse::parse_packet;
use keyd::parse::{parse_packet, Reply};

use keyd::agent::KeyDAgent;

fn main() {
    std::fs::remove_file("/tmp/test-keyd.sock").ok();
    let listener = UnixListener::bind("/tmp/test-keyd.sock").unwrap();
    let mut agent = KeyDAgent::new().unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("connect");
                let mut buf = vec![0u8; 4096];
                'handle: loop {
                    let r = stream.read(&mut buf);

                    match r {
                        Ok(r) => {
                            if r == 0 {
                                break 'handle;
                            }
                        }
                        Err(_e) => break 'handle,
                    }

                    let req = parse_packet(&buf);

                    match req {
                        Ok(req) => {
                            let reply = agent.process(req).unwrap_or_else(|_| Reply::failed());

                            stream.write(&reply);
                        }
                        Err(_) => {
                            let reply = Reply::failed();
                            stream.write(&reply);
                        }
                    }
                }
            }
            Err(_err) => {
                break;
            }
        }
    }
}
