#![cfg(unix)]

use std::os::unix::net::{UnixStream, UnixListener};
use std::os::raw;
use std::io::Read;
use std::io::Write;
// use keyd::parse::parse_packet;
use keyd::parse2::{parse_packet, Request, Reply};
use libsshkey::key::{KeyExt, HashType, Key};
use openssl::hash::MessageDigest;
use libsshkey::SSHBuffer;

fn main() {
    std::fs::remove_file("/tmp/test-keyd.sock").ok();
    let listener = UnixListener::bind("/tmp/test-keyd.sock").unwrap();
    let mut keys = vec![];

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("connect");
                let mut buf = vec![0u8; 4096];
                'handle: loop {
                    let r = stream.read(&mut buf);

                    match r {
                        Ok(r) => if r == 0 {
                            break'handle;
                        },
                        Err(e) => break'handle,
                    }

                    let req = parse_packet(&buf);
                    dbg!(&req);

                    let reply = if let Ok(req) = req {
                        match req {
                            Request::List => {
                                Reply::list(&keys)
                            },
                            Request::Add(key) => {
                                match &key {
                                    Key::Rsa(rsa) => {
                                        dbg!(rsa.fingerprint(HashType::SHA256).unwrap());
                                    },
                                    Key::EcdsaP256(key) | Key::EcdsaP384(key) | Key::EcdsaP521(key) => {
                                        dbg!(key.fingerprint(HashType::SHA256).unwrap());
                                    },
                                    _ => panic!()
                                }
                                keys.push(key);
                                Reply::success()
                            },
                            Request::Sign(fingerprint, data, flags) => {
                                let key = keys.iter().find(|key| {
                                    key.fingerprint(HashType::SHA256).unwrap() == fingerprint
                                });

                                let reply = match key {
                                    Some(key) => {
                                        dbg!(key.fingerprint(HashType::SHA256));
                                        let signature = match key {
                                            Key::Rsa(key) => key.sign(MessageDigest::sha256(), data).unwrap(),
                                            Key::EcdsaP256(key) => {
                                                let (r, s) = key.sign(MessageDigest::sha256(), data).unwrap();
                                                let mut buf = SSHBuffer::empty().unwrap();
                                                buf.put_string(r).unwrap();
                                                buf.put_string(s).unwrap();

                                                buf.to_vec()
                                            },
                                            Key::EcdsaP384(key) => {
                                                let (r, s) = key.sign(MessageDigest::sha384(), data).unwrap();
                                                let mut buf = SSHBuffer::empty().unwrap();
                                                buf.put_string(r).unwrap();
                                                buf.put_string(s).unwrap();

                                                buf.to_vec()
                                            },
                                            Key::EcdsaP521(key) => {
                                                let (r, s) = key.sign(MessageDigest::sha512(), data).unwrap();
                                                let mut buf = SSHBuffer::empty().unwrap();
                                                buf.put_string(r).unwrap();
                                                buf.put_string(s).unwrap();

                                                buf.to_vec()
                                            },
                                            _ => Vec::new(),
                                        };
                                        Reply::sign(key, signature)
                                    },
                                    None => {
                                        Reply::success()
                                    }
                                };

                                dbg!(&reply);

                                reply
                            }
                        }
                    } else {
                        Reply::success()
                    };

                    stream.write(&reply);
                }
            }
            Err(err) => {
                break;
            }
        }
    }

}
