use std::convert::TryFrom;
use std::marker::PhantomData;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{Err, IResult};
use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::{flat_map, map, map_res};
use nom::error::{ErrorKind, make_error, ParseError, VerboseError};
use nom::number::complete::be_u32;
use nom::sequence::tuple;

use ClientMessageType::*;

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


#[derive(Debug)]
pub enum Request {
    List,
    Add(Key),
}

#[derive(Debug)]
pub enum Key {
    ECDSA(ECDSA),
    RSA(),
}

#[derive(Debug)]
pub struct ECDSA {
    key_type: String,
    curve_name: String,
    q: Vec<u8>,
    d: Vec<u8>,
    comment: String,
}

type KResult<I, O> = IResult<I, O, VerboseError<I>>;

impl ECDSA {
    pub fn parse(key_type: String, input: &[u8]) -> KResult<&[u8], Self> {
        let (input, curve_name) = map_res(flat_map(be_u32, take), |x: &[u8]| String::from_utf8(x.to_vec()))(input)?;

        let (input, len) = be_u32(input)?;
        let (input, q) = take(len)(input)?;

        let (input, len) = be_u32(input)?;
        let (input, d) = take(len)(input)?;

        let (input, comment) = map_res(flat_map(be_u32, take), |x: &[u8]| String::from_utf8(x.to_vec()))(input)?;

        Ok((input, ECDSA {
            key_type,
            curve_name,
            q: q.to_vec(),
            d: d.to_vec(),
            comment,
        }))
    }
}

pub fn parse_packet(input: &[u8]) -> KResult<&[u8], Request> {
    let (input, (len, ty)) = tuple((
        be_u32,
        map_res(take(1usize), |x: &[u8]| ClientMessageType::try_from(x[0]))
    ))(input)?;

    match ty {
        SshAgentRequestIdentities => {
            Ok((input, Request::List))
        }
        SshAgentAddIdentity => {
            let (input, key_ty) = flat_map(be_u32, take)(input)?;

            let (_, key_ty) = map_res(alt((
                tag("ecdsa-sha2-nistp256"),
                tag("ecdsa-sha2-nistp384"),
                tag("ecdsa-sha2-nistp521")
            )), |x| std::str::from_utf8(x))(key_ty)?;

            match key_ty {
                "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                    let (input, key) = ECDSA::parse(key_ty.to_owned(), input)?;

                    return Ok((input, Request::Add(Key::ECDSA(key))));
                }
                _ => {
                    unreachable!()
                }
            }

            Err(Err::Failure(nom::error::make_error(input, nom::error::ErrorKind::ParseTo)))
        }
        _ => {
            unimplemented!()
        }
    }
}


#[test]
fn test1() {
    let buf =
        [
            0u8,
            0,
            0,
            160,
            17,
            0,
            0,
            0,
            19,
            101,
            99,
            100,
            115,
            97,
            45,
            115,
            104,
            97,
            50,
            45,
            110,
            105,
            115,
            116,
            112,
            50,
            53,
            54,
            0,
            0,
            0,
            8,
            110,
            105,
            115,
            116,
            112,
            50,
            53,
            54,
            0,
            0,
            0,
            65,
            4,
            35,
            255,
            171,
            254,
            246,
            31,
            211,
            135,
            49,
            75,
            74,
            207,
            110,
            53,
            18,
            143,
            152,
            146,
            27,
            1,
            90,
            4,
            128,
            106,
            150,
            86,
            82,
            24,
            87,
            28,
            112,
            135,
            62,
            47,
            94,
            89,
            207,
            122,
            142,
            247,
            121,
            172,
            21,
            86,
            14,
            91,
            155,
            116,
            75,
            89,
            111,
            61,
            136,
            201,
            57,
            104,
            212,
            92,
            142,
            241,
            62,
            199,
            245,
            63,
            0,
            0,
            0,
            33,
            0,
            161,
            117,
            116,
            208,
            188,
            135,
            59,
            54,
            185,
            144,
            64,
            127,
            96,
            201,
            132,
            225,
            96,
            44,
            209,
            237,
            191,
            20,
            190,
            174,
            224,
            51,
            34,
            57,
            65,
            47,
            31,
            221,
            0,
            0,
            0,
            14,
            116,
            121,
            97,
            110,
            64,
            97,
            114,
            99,
            104,
            108,
            105,
            110,
            117,
            120,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0, ];

    let (_, req) = parse_packet(&buf).unwrap();
    dbg!(req);
}