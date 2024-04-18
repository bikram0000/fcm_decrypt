extern crate base64;
extern crate ece;
extern crate serde;
extern crate serde_json;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use ece::EcKeyComponents;
use serde_json::Value;
use std::{
    error::Error,
    ffi::{CString, CStr},
    os::raw::c_char,
};

#[no_mangle]
pub extern "C" fn decrypt_message(message_json: *const c_char) -> *mut c_char {
    let message_json = unsafe { CStr::from_ptr(message_json).to_str().unwrap() };

    let message: Value = serde_json::from_str(message_json).unwrap();

    let result = match decrypt_message_internal(&message) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Error: {}", err);
            return CString::new("").unwrap().into_raw();
        }
    };

    let result_str = CString::new(result).unwrap();
    result_str.into_raw()
}

fn decrypt_message_internal(message: &Value) -> Result<String, Box<dyn Error>> {
    let raw_data = message["object"]["rawData"]
        .as_array()
        .ok_or("Missing rawData field")?;
    let raw_data_vec: Vec<u8> = raw_data
        .iter()
        .map(|v| v.as_u64().ok_or("Invalid raw data format").map(|n| n as u8))
        .collect::<Result<Vec<u8>, _>>()?;

    let crypto_key = message["object"]["appData"]
        .as_array()
        .and_then(|arr| find_value_by_key(&arr, "crypto-key"))
        .ok_or("Missing crypto-key field")?
        .to_string();

    let encryption = message["object"]["appData"]
        .as_array()
        .and_then(|arr| find_value_by_key(&arr, "encryption"))
        .ok_or("Missing encryption field")?
        .to_string();

    let private_key = message["keys"]["privateKey"]
        .as_str()
        .ok_or("Missing privateKey field")?
        .to_string();

    let public_key = message["keys"]["publicKey"]
        .as_str()
        .ok_or("Missing publicKey field")?
        .to_string();

    let auth_secret = message["keys"]["authSecret"]
        .as_str()
        .ok_or("Missing authSecret field")?
        .to_string();

    let crypto_key_bytes = URL_SAFE.decode(&crypto_key[3..])?;
    let encryption_bytes = URL_SAFE.decode(&encryption[5..])?;
    let public_key_bytes = URL_SAFE_NO_PAD.decode(public_key.as_bytes())?;
    let private_key_bytes = URL_SAFE_NO_PAD.decode(private_key.as_bytes())?;
    let auth_secret_bytes = URL_SAFE_NO_PAD.decode(auth_secret.as_bytes())?;

    let components = EcKeyComponents::new(private_key_bytes, public_key_bytes);

    let record_size: u32 = 4096;
    let encrypted_block =
        ece::legacy::AesGcmEncryptedBlock::new(&crypto_key_bytes, &encryption_bytes, record_size, raw_data_vec)?;
    let data_bytes =
        ece::legacy::decrypt_aesgcm(&components, &auth_secret_bytes, &encrypted_block)?;

    Ok(String::from_utf8(data_bytes)?)
}

fn find_value_by_key<'a>(arr: &'a [Value], key: &str) -> Option<&'a str> {
    arr.iter().find_map(|elem| {
        let obj = elem.as_object()?;
        let k = obj.get("key")?.as_str()?;
        if k == key {
            obj.get("value")?.as_str()
        } else {
            None
        }
    })
}