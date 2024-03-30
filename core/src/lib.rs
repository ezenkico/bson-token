use std::{collections::HashMap, io, time::{SystemTime, UNIX_EPOCH}};

use bson::{self, doc, Bson, Document};
use ring::{hmac, rand, signature::{self, RsaEncoding}};
use serde::{Serialize, Deserialize};

pub fn invalid_data(message: String) -> io::Error{
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn map_invalid_data(err: impl std::error::Error) -> io::Error{
    invalid_data(format!("{err}"))
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BsonTokenHeader{
    pub alg: String,
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub kid: Option<String>
}

impl From<Document> for BsonTokenHeader{
    fn from(mut value: Document) -> Self {
        let alg = match value.remove("alg"){
            Some(Bson::String(alg)) => alg,
            _ => "HS256".to_string()
        };

        let typ = match value.remove("typ") {
            Some(Bson::String(typ)) => Some(typ),
            _ => None
         };

         let cty = match value.remove("cty") {
             Some(Bson::String(cty)) => Some(cty),
             _ => None
         };

         let kid = match value.remove("kid"){
            Some(Bson::String(kid)) => Some(kid),
            _ => None
         };

        Self{
            alg,
            typ,
            cty,
            kid
        }
    }
}

impl Into<Document> for BsonTokenHeader {
    fn into(self) -> Document {
        let mut res = doc! {
            "alg": self.alg
        };

        if let Some(typ) = self.typ{
            res.insert("typ", typ);
        }

        if let Some(cty) = self.cty{
            res.insert("cty", cty);
        }

        if let Some(kid) = self.kid{
            res.insert("kid", kid);
        }

        res
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BsonToken{
    pub header: BsonTokenHeader,
    pub payload: Document
}

fn doc_to_binary(data: Document) -> io::Result<Vec<u8>>{
    let mut bin = Vec::new();

    data.to_writer(&mut bin).map_err(map_invalid_data)?;

    Ok(bin)
}

fn sign_rsa(data: &[u8], secret: &[u8], encoding: &'static dyn RsaEncoding) -> io::Result<Vec<u8>>{
    let private_key = match signature::RsaKeyPair::from_der(secret){
        Ok(k) => k,
        Err(e) => return Err(invalid_data(format!("{e}")))
    };

    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; private_key.public().modulus_len()];

    match private_key.sign(encoding, &rng, data, &mut signature){
        Ok(_) => {}
        Err(e) => return Err(invalid_data(format!("{e}")))
    }

    Ok(signature)
}

fn sign_hs(data: &[u8], secret: &[u8], encoding: hmac::Algorithm) -> io::Result<Vec<u8>>{
    let key = hmac::Key::new(encoding, secret);

    let tag = hmac::sign(&key, data);

    Ok(tag.as_ref().to_vec())
}

fn validate_rsa(data: &[u8], secret: &[u8], sig: &[u8], algorithm: &'static dyn signature::VerificationAlgorithm) -> io::Result<()>{
    let public_key = signature::UnparsedPublicKey::new(algorithm, secret);
    match public_key.verify(data, sig){
        Ok(_) => return Ok(()),
        Err(e) => return Err(invalid_data(format!("{e}")))
    }
}

fn validate_hs(data: &[u8], secret: &[u8], sig: &[u8], encoding: hmac::Algorithm) -> io::Result<()>{
    let key = hmac::Key::new(encoding, secret);
    
    match hmac::verify(&key, data, sig) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(invalid_data(format!("{e}")))
    }
}

fn get_lengths(data: &Vec<u8>) -> io::Result<(usize, usize)>{
    let len = data.len();

    if len < 4{
        return Err(invalid_data("Token is to short".into()));   
    }

    let mut h_len: usize = 0;

    for i in 0..4{
        h_len |= (data[i] as usize) << (i * 8);
    }

    if len < (h_len + 4){
        return Err(invalid_data("Token is to short".into()));
    }

    let mut p_len: usize = 0;

    for i in 0..4 {
        p_len |= (data[i] as usize) << (i * 8);
    }

    Ok((h_len, p_len))
}

fn check_expiration(payload: &Document) -> io::Result<()>{
    let time = SystemTime::now().duration_since(UNIX_EPOCH).map_err(map_invalid_data)?;
    let seconds = time.as_secs_f64();
    match payload.get("exp"){
        Some(exp) => {
            
            let exp = match exp{
                Bson::Double(exp) => *exp,
                Bson::Int32(exp) => (*exp) as f64,
                Bson::Int64(exp) => (*exp) as f64,
                _ => return Err(invalid_data("No expiration present".into()))
            };
            if seconds > exp{
                return Err(invalid_data("Token is expired".into()));
            }
        }
        None => return Err(invalid_data("No expiration present".into()))
    }
    match payload.get("nbf") {
        Some(nbf) => {
            let nbf = match nbf {
                Bson::Double(nbf) => *nbf,
                Bson::Int32(nbf) => (*nbf) as f64,
                Bson::Int64(nbf) => (*nbf) as f64,
                _ => return Ok(())
            };

            if seconds > nbf{
                return Err(invalid_data("Token is not available yet".into()));
            }
        }
        None => {}
    }

    Ok(())
}

impl BsonToken {
    pub fn to_binary(self, secret: BsonSecret) -> io::Result<Vec<u8>>{
        let (
            header,
            payload
        ) = (
            self.header,
            self.payload
        );

        let secret = match secret {
            BsonSecret::Single(s) => s,
            BsonSecret::Multiple(s) => match &header.kid {
                Some(kid) => s.get_secret(kid)?,
                None => return Err(invalid_data("No secret found".into()))
            }
        };

        let alg = header.alg.clone();

        let mut data = doc_to_binary(header.into())?;
        data.extend(doc_to_binary(payload)?);

        let sig = match alg.as_str(){
            "RS256" => sign_rsa(data.as_slice(), secret.as_slice(), &signature::RSA_PKCS1_SHA256)?,
            "RS384" => sign_rsa(data.as_slice(), secret.as_slice(), &signature::RSA_PKCS1_SHA384)?,
            "RS512" => sign_rsa(data.as_slice(), secret.as_slice(), &signature::RSA_PKCS1_SHA512)?,
            "HS384" => sign_hs(data.as_slice(), secret.as_slice(), hmac::HMAC_SHA384)?,
            "HS512" => sign_hs(data.as_slice(), secret.as_slice(), hmac::HMAC_SHA512)?,
            _ => sign_hs(data.as_slice(), secret.as_slice(), hmac::HMAC_SHA512)?,
        };

        data.extend(sig);

        Ok(data)
    }

    pub fn verify(mut data: Vec<u8>, secret: BsonSecret, check_exp: bool) -> io::Result<Self>{
        let (h_len, p_len) = get_lengths(&data)?;
        let total = h_len + p_len;

        let sig = data.split_off(total);

        let mut header = Vec::with_capacity(h_len);

        for i in 0..h_len{
            header.push(data[i]);
        }

        let header: BsonTokenHeader = Document::from_reader(io::Cursor::new(header)).map_err(map_invalid_data)?.into();

        let secret = match secret {
            BsonSecret::Single(s) => s,
            BsonSecret::Multiple(s) => match &header.kid {
                Some(kid) => s.get_secret(kid)?,
                None => return Err(invalid_data("No secret found".into()))
            }
        };

        match header.alg.as_str(){
            "RS256" => validate_rsa(data.as_slice(), secret.as_slice(), sig.as_slice(), &signature::RSA_PKCS1_2048_8192_SHA256)?,
            "RS384" => validate_rsa(data.as_slice(), secret.as_slice(), sig.as_slice(), &signature::RSA_PKCS1_2048_8192_SHA384)?,
            "RS512" => validate_rsa(data.as_slice(), secret.as_slice(), sig.as_slice(), &signature::RSA_PKCS1_2048_8192_SHA512)?,
            "HS384" => validate_hs(data.as_slice(), secret.as_slice(), sig.as_slice(), hmac::HMAC_SHA384)?,
            "HS512" => validate_hs(data.as_slice(), secret.as_slice(), sig.as_slice(), hmac::HMAC_SHA512)?,
            _ => validate_hs(data.as_slice(), secret.as_slice(), sig.as_slice(), hmac::HMAC_SHA512)?,
        }

        let payload = data.split_off(h_len);

        drop(data);

        let payload = Document::from_reader(io::Cursor::new(payload)).map_err(map_invalid_data)?;

        if check_exp{
            check_expiration(&payload)?;
        }

        Ok(Self { header, payload })
    }

    pub fn extract(mut data: Vec<u8>) -> io::Result<Self>{
        let (h_len, p_len) = get_lengths(&data)?;
        let total = h_len + p_len;

        let _ = data.split_off(total);

        let mut header = Vec::with_capacity(h_len);

        for i in 0..h_len{
            header.push(data[i]);
        }

        let header: BsonTokenHeader = Document::from_reader(io::Cursor::new(header)).map_err(map_invalid_data)?.into();

        let payload = data.split_off(h_len);

        drop(data);

        let payload = Document::from_reader(io::Cursor::new(payload)).map_err(map_invalid_data)?;

        Ok(Self { header, payload })
    }
}

#[derive(Clone)]
pub struct MultipleBsonSecret{
    pub secrets: HashMap<String, Vec<u8>>,
    pub default: Option<String>
}

impl MultipleBsonSecret{
    pub fn get_secret(mut self, key: &String) -> io::Result<Vec<u8>>{
        match self.secrets.remove(key){
            Some(s) => return Ok(s),
            None => match self.default {
                Some(d) => match self.secrets.remove(&d) {
                    Some(s) => return Ok(s),
                    None => {}
                }
                None => {}
            }
        }
        return Err(invalid_data("No secret found".into()))
    }
}

#[derive(Clone)]
pub enum BsonSecret {
    Single(Vec<u8>),
    Multiple(MultipleBsonSecret)
}


