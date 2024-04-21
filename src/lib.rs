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
    // Print the input message_json
    let message_json_str = unsafe { CStr::from_ptr(message_json).to_str().unwrap() };
    // println!("Input message (JSON): {}", message_json_str);

    // Handle potential deserialization error
    let message: Result<Value, serde_json::Error> = serde_json::from_str(message_json_str);
    match message {
        Ok(message) => {
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
        Err(err) => {
            eprintln!("Error deserializing JSON: {}", err);
            return CString::new("").unwrap().into_raw();
        }
    }
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


#[cfg(test)]
mod tests {
    use super::*; // Use crate to access library functions
    #[test]
    fn test_decrypt_message() {
        // Define your test JSON data
        // let test_json = json!({"object":{"id":"B4362F8D","from":"BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4","category":"org.chromium.linux","appData":[{"key":"google.source","value":"webpush"},{"key":"encryption","value":"salt=2-XbF7yVGnxuu6xf2HCWrg=="},{"key":"subtype","value":"wp:receiver.push.com#7c47ef8f-ad1d-45c0-b048-e37b8d95f092"},{"key":"crypto-key","value":"dh=BBchCtcAXtA-ghgjOPK_I9I3JQ6A3Huj58HHwq4ScfLiQWKhWDe7qPinGsNfdV31kNfN3e_-UvX28Wcvpqk0JBg="}],"persistentId":"0:1711623408410794%7031b2e6f9fd7ecd","ttl":2419200,"sent":"1711623408408","rawData":[144,100,24,211,44,137,162,184,201,92,144,234,7,197,77,100,149,56,136,47,103,51,248,229,49,83,203,100,91,191,11,118,151,111,8,55,72,14,228,148,33,72,59,211,84,32,112,20,184,10,11,117,105,172,109,21,163,165,149,84,19,5,18,7,105,183,142,104,117,239,128,161,91,56,75,226,113,36,1,140,53,168,206,233,83,118,186,247,86,217,163,59,57,183,47,194,105,155,78,88,176,203,166,85,189,101,158,207,145,115,178,125,3,150,177,90,107,58,247,207,174,225,24,81,255,198,170,76,88,3,193,213,204,173,241,188,189,165,32,250,205,243,75,195,200,166,63,52,253,199,109,18,21,30,145,50,220,163,34,19,152,148,190,75,234,218,135,238,200,253,113,100,172,46,225,22,189,246,221,5,48,188,238,208,34,145,104,91,225,200,112,59,227,155,184,163,37,103,48,161,164,72,71,49,136,89,218,122,139,20,43,120,163,161,175,136,89,152,67,148,198,7,83,107,134,132,176,203,239,178,247,178,153,110,214,223,237,251,20,184,125,243,18,8,40,105,135,133,51,190,243,0,160,218,12,150,219,10,95,67,37,25,192,43,245]},"keys":{"privateKey":"mxS1cWvYGFxJJS8RTsOFkW5VqRyL4k6mIH0K3V47aHQ","publicKey":"BF4--ivRFQqtqhVlEbK6HoBlznFZu9lcAwpps-IDwTpuzLgxUQkRpMsxTnOUUHdbZK4XmFFo3c4ArvxXOcJHDPc","authSecret":"UG5PMDBLZkw5WHVFWmp0Vw"}});

        // Convert the JSON to a string
        // let test_json_str: String = serde_json::to_string(&test_json).unwrap();
        let test_json_str = r#"{"object":{"id":"B4362F8D","from":"BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4","category":"org.chromium.linux","appData":[{"key":"google.source","value":"webpush"},{"key":"encryption","value":"salt=2-XbF7yVGnxuu6xf2HCWrg=="},{"key":"subtype","value":"wp:receiver.push.com#7c47ef8f-ad1d-45c0-b048-e37b8d95f092"},{"key":"crypto-key","value":"dh=BBchCtcAXtA-ghgjOPK_I9I3JQ6A3Huj58HHwq4ScfLiQWKhWDe7qPinGsNfdV31kNfN3e_-UvX28Wcvpqk0JBg="}],"persistentId":"0:1711623408410794%7031b2e6f9fd7ecd","ttl":2419200,"sent":"1711623408408","rawData":[144,100,24,211,44,137,162,184,201,92,144,234,7,197,77,100,149,56,136,47,103,51,248,229,49,83,203,100,91,191,11,118,151,111,8,55,72,14,228,148,33,72,59,211,84,32,112,20,184,10,11,117,105,172,109,21,163,165,149,84,19,5,18,7,105,183,142,104,117,239,128,161,91,56,75,226,113,36,1,140,53,168,206,233,83,118,186,247,86,217,163,59,57,183,47,194,105,155,78,88,176,203,166,85,189,101,158,207,145,115,178,125,3,150,177,90,107,58,247,207,174,225,24,81,255,198,170,76,88,3,193,213,204,173,241,188,189,165,32,250,205,243,75,195,200,166,63,52,253,199,109,18,21,30,145,50,220,163,34,19,152,148,190,75,234,218,135,238,200,253,113,100,172,46,225,22,189,246,221,5,48,188,238,208,34,145,104,91,225,200,112,59,227,155,184,163,37,103,48,161,164,72,71,49,136,89,218,122,139,20,43,120,163,161,175,136,89,152,67,148,198,7,83,107,134,132,176,203,239,178,247,178,153,110,214,223,237,251,20,184,125,243,18,8,40,105,135,133,51,190,243,0,160,218,12,150,219,10,95,67,37,25,192,43,245]},"keys":{"privateKey":"mxS1cWvYGFxJJS8RTsOFkW5VqRyL4k6mIH0K3V47aHQ","publicKey":"BF4--ivRFQqtqhVlEbK6HoBlznFZu9lcAwpps-IDwTpuzLgxUQkRpMsxTnOUUHdbZK4XmFFo3c4ArvxXOcJHDPc","authSecret":"UG5PMDBLZkw5WHVFWmp0Vw"}}"#;

        let cstring = std::ffi::CString::new(test_json_str).unwrap();
        let result_ptr = decrypt_message(cstring.as_ptr());
        // Call the decrypt_message function

        // Convert the result back to a string
        let result_str = unsafe { std::ffi::CString::from_raw(result_ptr) };
        let result = result_str.to_str().unwrap();
      let json_string = r#"{"data":{"table_no":"32","title":"Some title of","body":"Some hjgjhgjghjg","order_id":"1646"},"from":"519179141595","priority":"high","notification":{"title":"Some titlde4","body":"Some body"},"fcmMessageId":"fc9f25f9-a42a-453a-87e7-86168d6e2317"}"#;
        // Add your assertions here to check the result
        assert_eq!(result,json_string);
    }


}