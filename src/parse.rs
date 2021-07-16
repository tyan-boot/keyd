use crate::error::Error;
use crate::store::models::{Key, KeyType};
use bytes::{Buf, Bytes, BytesMut};
use derive_try_from_primitive::TryFromPrimitive;
use libsshkey::key::{EcGroup, Ecdsa, HashType, Rsa};
use libsshkey::{key::Key as RawKey, SSHBuffer};
use std::convert::TryFrom;
use std::ops::Deref;

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
enum ClientMessageType {
    SshAgentRequestIdentities = 11,
    SshAgentSignRequest = 13,
    SshAgentAddIdentity = 17,
    SshAgentRemoveIdentity = 18,
    SshAgentRemoveAllIdentities = 19,
    SshAgentAddIdConstrained = 25,
    SshAgentAddSmartCardKey = 20,
    SshAgentRemoveSmartCardKey = 21,
    SshAgentLock = 22,
    SshAgentUnlock = 23,
    SshAgentAddSmartCardKeyConstrained = 26,
    SshAgentExtension = 27,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
enum ServerResponseType {
    SshAgentFailure = 5,
    SshAgentSuccess = 6,
    SshAgentExtensionFailure = 28,
    SshAgentIdentitiesAnswer = 12,
    SshAgentSignResponse = 14,
}

#[derive(Debug)]
pub enum Request {
    List,
    Add(RawKey),
    Sign(String, Bytes, u32),
}

pub fn parse_packet(input: impl AsRef<[u8]>) -> anyhow::Result<Request> {
    let input = input.as_ref();
    let mut input = BytesMut::from(input);

    let len = input.get_u32();
    input.truncate(len as usize);

    let ty = input.get_u8();

    let ty =
        ClientMessageType::try_from(ty).map_err(|e| anyhow::anyhow!("unexpected ty: {}", e))?;

    match ty {
        ClientMessageType::SshAgentRequestIdentities => Ok(Request::List),
        ClientMessageType::SshAgentAddIdentity => {
            let buf = SSHBuffer::from_bytes_mut(input)?;
            let key_type = buf.peek_string()?;

            if key_type.starts_with("ecdsa-sha2-") {
                let key = Ecdsa::import_private_blob(buf)?;
                let key = match key.group() {
                    EcGroup::P256 => RawKey::EcdsaP256(key),
                    EcGroup::P384 => RawKey::EcdsaP384(key),
                    EcGroup::P521 => RawKey::EcdsaP521(key),
                };

                Ok(Request::Add(key))
            } else if key_type.starts_with("ssh-rsa") {
                let key = Rsa::import_private_blob(buf)?;
                Ok(Request::Add(RawKey::Rsa(key)))
            } else {
                anyhow::bail!("unsupported key");
            }
        }
        ClientMessageType::SshAgentSignRequest => {
            let mut buf = SSHBuffer::from_bytes_mut(input)?;
            let blob = buf.get_string()?;
            let key = libsshkey::key::parse_public_blob(blob)?;
            let fingerprint = key.fingerprint(HashType::SHA256)?;

            let data = buf.get_string()?;
            let flags = buf.get_u32();

            Ok(Request::Sign(fingerprint, data, flags))
        }
        _ => anyhow::bail!("unsupported operate"),
    }
}

#[derive(Debug)]
pub struct Reply(Vec<u8>);

impl Deref for Reply {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl Reply {
    fn fix_len(buf: &mut Vec<u8>) {
        let len = buf.len() as u32 - 4;
        buf[0..4].copy_from_slice(&len.to_be_bytes());
    }

    pub fn success() -> Reply {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(&0u32.to_be_bytes());

        buf.push(ServerResponseType::SshAgentSuccess as u8);

        Reply::fix_len(&mut buf);

        Reply(buf)
    }

    pub fn failed() -> Reply {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(&0u32.to_be_bytes());

        buf.push(ServerResponseType::SshAgentFailure as u8);

        Reply::fix_len(&mut buf);

        Reply(buf)
    }

    pub fn list(keys: &[Key]) -> Reply {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(&0u32.to_be_bytes());

        buf.push(ServerResponseType::SshAgentIdentitiesAnswer as u8);
        buf.extend(&(keys.len() as u32).to_be_bytes());

        let buf = (|| {
            let mut buf = SSHBuffer::new(buf)?;

            for key in keys {
                let public = key.public_blob()?;
                buf.put_string(&*public)?;
                buf.put_string(key.comment().unwrap_or_default())?;
            }

            Ok::<_, Error>(buf.to_vec())
        })();

        match buf {
            Ok(mut buf) => {
                Reply::fix_len(&mut buf);

                Reply(buf)
            }
            Err(_) => Reply::failed(),
        }
    }

    pub fn sign(key_type: KeyType, signature: impl AsRef<[u8]>) -> Reply {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf.push(ServerResponseType::SshAgentSignResponse as u8);
        let signature = signature.as_ref();

        let sig_buf = (|| {
            let mut sig_buf = SSHBuffer::empty()?;

            match key_type {
                KeyType::Rsa => {
                    sig_buf.put_string("ssh-rsa")?;
                }
                KeyType::EcdsaP256 => {
                    sig_buf.put_string("ecdsa-sha2-nistp256")?;
                }
                KeyType::EcdsaP384 => {
                    sig_buf.put_string("ecdsa-sha2-nistp384")?;
                }
                KeyType::EcdsaP521 => {
                    sig_buf.put_string("ecdsa-sha2-nistp521")?;
                }
                _ => {}
            }
            sig_buf.put_string(&signature)?;

            Ok::<_, Error>(sig_buf)
        })();

        match sig_buf {
            Ok(sig_buf) => {
                buf.extend(&(sig_buf.len() as u32).to_be_bytes());
                buf.extend(&*sig_buf);

                Reply::fix_len(&mut buf);

                Reply(buf)
            }
            Err(_) => Reply::failed(),
        }
    }
}
