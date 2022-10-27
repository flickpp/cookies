// Cookie implementation
use std::collections::HashMap;
use std::ops::Add;
use std::result;
use std::time;

use random_fast_rng::{FastRng, Random};

#[macro_use]
extern crate lazy_static;

#[derive(Debug)]
pub enum Error {
    InvalidSessionCookie(&'static str),
    InvalidUserId(&'static str),
    UserIdWrongLength,
    InvalidUserToken(&'static str),
    InvalidLoginToken(&'static str),
    BadDigest,
    LoginTokenExpired,
    InvalidLoginCookie(&'static str),
    InvalidUserCookie(&'static str),
    InvalidFlag,
}

impl Error {
    pub fn reason_str(self) -> &'static str {
        use Error::*;
        match self {
            InvalidSessionCookie(s) => s,
            InvalidUserId(s) => s,
            UserIdWrongLength => "user_id wrong length",
            InvalidUserToken(s) => s,
            InvalidLoginToken(s) => s,
            BadDigest => "invalid digest",
            LoginTokenExpired => "login token has expired",
            InvalidLoginCookie(s) => s,
            InvalidUserCookie(s) => s,
            InvalidFlag => "flag is unrecognised",
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

// SessionId is a 32 char hexstring
pub type SessionId<'a> = &'a str;

// UserId is a 32 char hexstring
pub type UserId<'a> = &'a str;

// Login Flags
pub type LoginFlags = u64;

const LOGIN_FLAGS: &[&str] = &["employee"];

lazy_static! {
    static ref LOGIN_FLAGS_MAP: HashMap<&'static str, LoginFlags, fasthash::murmur2::Hash32> =
        build_login_flags();
}

pub struct LoginId<'a> {
    // user_id is a 32 char hexstring
    pub user_id: UserId<'a>,

    // flags are an authorization mechanism
    pub flags: LoginFlags,
}

fn build_login_flags() -> HashMap<&'static str, LoginFlags, fasthash::murmur2::Hash32> {
    let mut map = HashMap::with_hasher(fasthash::murmur2::Hash32);
    for (n, f) in LOGIN_FLAGS.iter().enumerate() {
        map.insert(*f, 1 << n);
    }

    map
}

pub fn flag_from_str(flag: &str) -> Result<LoginFlags> {
    LOGIN_FLAGS_MAP
        .get(flag)
        .ok_or(Error::InvalidFlag)
        .map(|i| *i)
}

pub fn flags_from_strs(flags: &[&str]) -> Result<LoginFlags> {
    let mut ans = 0;
    for f in flags {
        ans |= flag_from_str(f)?;
    }

    Ok(ans)
}

impl<'a> LoginId<'a> {
    pub fn has_flags(&self, flags: LoginFlags) -> bool {
        flags & self.flags == flags
    }

    pub fn flag_strs(&self) -> String {
        let mut ans = vec![];
        for (k, v) in LOGIN_FLAGS_MAP.iter() {
            if *v & self.flags == *v {
                ans.push(*k);
            }
        }

        ans.join(",")
    }
}

pub fn new_session_cookie(session_salt: &[u8; 32]) -> String {
    let mut rng = FastRng::new();
    let session_id: [u8; 16] = rng.gen();
    let mut digest_buf: [u8; 16] = [0; 16];

    compute_digest(&session_id[..], &mut digest_buf, session_salt);

    format!("{}-{}", hex::encode(session_id), hex::encode(digest_buf))
}

pub fn parse_session_cookie<'a>(session_salt: &[u8; 32], cookie: &'a str) -> Result<SessionId<'a>> {
    if cookie.len() != 65 {
        return Err(Error::InvalidSessionCookie("expected length 65"));
    }

    let parts = cookie.split('-').collect::<Vec<&str>>();
    if parts.len() != 2 {
        return Err(Error::InvalidSessionCookie("expected a single -"));
    }

    // Decode the parts
    let session_id = match hex::decode(parts[0]) {
        Ok(i) => i,
        Err(_) => {
            return Err(Error::InvalidSessionCookie("not a hexstring"));
        }
    };

    let digest = match hex::decode(parts[1]) {
        Ok(i) => i,
        Err(_) => {
            return Err(Error::InvalidSessionCookie("not a hexstring"));
        }
    };

    if session_id.len() != 16 {
        return Err(Error::InvalidSessionCookie("session_id wrong length"));
    }

    let digest = if digest.len() == 16 {
        let mut d: [u8; 16] = [0; 16];
        for (a, b) in d.iter_mut().zip(digest.into_iter()) {
            *a = b;
        }
        d
    } else {
        return Err(Error::InvalidSessionCookie("digest is wrong length"));
    };

    check_digest_match(session_salt, &session_id, &digest)?;

    Ok(parts[0])
}

pub fn new_user_token(user_token_salt: &[u8; 32], user_id: &[u8; 16]) -> String {
    let mut digest: [u8; 16] = [0; 16];
    compute_digest(user_id, &mut digest, user_token_salt);
    let mut token = Vec::with_capacity(32);
    token.extend(user_id);
    token.extend(digest);
    base64_url::encode(&token)
}

pub fn new_user_cookie(user_cookie_salt: &[u8; 32], user_tk: &str) -> Result<String> {
    let tk =
        base64_url::decode(user_tk).map_err(|_| Error::InvalidUserToken("not base64 encoded"))?;

    if tk.len() != 32 {
        return Err(Error::InvalidUserToken("user token wrong length"));
    }

    let user_id = &tk[..16];
    let mac = &tk[16..];
    let mut digest: [u8; 16] = [0; 16];
    compute_digest(user_id, &mut digest, user_cookie_salt);
    if digest != mac {
        return Err(Error::InvalidUserToken("digest does not match"));
    }

    Ok(format!("{}-{}", hex::encode(user_id), hex::encode(mac)))
}

pub fn parse_user_cookie<'a>(
    user_cookie_salt: &[u8; 32],
    user_cookie: &'a str,
) -> Result<UserId<'a>> {
    let parts = user_cookie.split('-').collect::<Vec<&str>>();
    if parts.len() != 2 {
        return Err(Error::InvalidUserCookie("does not have two parts"));
    }

    let user_id =
        hex::decode(parts[0]).map_err(|_| Error::InvalidUserCookie("user_id not hexstring"))?;
    let mac = hex::decode(parts[1]).map_err(|_| Error::InvalidUserCookie("mac not hexstring"))?;

    let mut digest: [u8; 16] = [0; 16];
    compute_digest(&user_id, &mut digest, user_cookie_salt);
    if digest != mac[..] {
        return Err(Error::InvalidUserCookie("invalid digest"));
    }

    Ok(parts[0])
}

// new_login_cookie will build a login cookie from a login token
pub fn new_login_cookie(
    login_cookie_salt: &[u8; 32],
    login_token_salt: &[u8; 32],
    login_token: &str,
    // time cookie will be valid for
    valid_time: time::Duration,
) -> Result<String> {
    parse_login_token(login_token_salt, login_token)
        .map(|(user_id, flags)| create_login_cookie(login_cookie_salt, &user_id, flags, valid_time))
}

fn create_login_cookie(
    login_cookie_salt: &[u8; 32],
    user_id: &[u8; 16],
    flags: LoginFlags,
    valid_time: time::Duration,
) -> String {
    let flags_bytes = flags.to_be_bytes();

    let expiry_time = time::SystemTime::now()
        .add(valid_time)
        .duration_since(time::UNIX_EPOCH)
        .expect("couldn't get system time")
        .as_secs()
        .to_be_bytes();

    let mut data = vec![];
    data.extend(&expiry_time);
    data.extend(user_id);
    data.extend(flags_bytes);

    let mut digest: [u8; 16] = [0; 16];
    compute_digest(&data, &mut digest, login_cookie_salt);

    format!(
        "00-{}-{}-{}-{}",
        hex::encode(expiry_time),
        hex::encode(user_id),
        hex::encode(flags_bytes),
        hex::encode(digest)
    )
}

pub fn parse_login_cookie<'a>(
    login_cookie_salt: &[u8; 32],
    cookie: &'a str,
) -> Result<LoginId<'a>> {
    if cookie.len() != 102 {
        return Err(Error::InvalidLoginCookie("wrong length"));
    }

    let parts = cookie.split('-').collect::<Vec<&str>>();
    if parts.len() != 5 {
        return Err(Error::InvalidLoginCookie("doesn't contain five parts"));
    }

    if parts[0] != "00" {
        return Err(Error::InvalidLoginCookie("unrecognised version"));
    }

    // Check the lengths and decode the hexstrings, build data
    let mut parts_bytes = vec![];
    for (n, p) in parts.iter().enumerate() {
        if n == 0 {
            // Version
            continue;
        } else if n == 1 || n == 3 {
            // expiry time, flags
            if p.len() != 16 {
                return Err(Error::InvalidLoginCookie("badly formatted"));
            }
        } else if n == 2 || n == 4 {
            // user_id, digest
            if p.len() != 32 {
                return Err(Error::InvalidLoginCookie("badly formatted"));
            }
        }

        // decode the hexstring
        match hex::decode(p) {
            Ok(p) => parts_bytes.push(p),
            Err(_) => {
                return Err(Error::InvalidLoginCookie("badly formatted"));
            }
        }
    }

    // Check the digest
    let mut digest_buf: [u8; 16] = [0; 16];
    for (a, b) in digest_buf.iter_mut().zip(&parts_bytes[3]) {
        *a = *b;
    }

    let data = parts_bytes[..3]
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<u8>>();
    check_digest_match(login_cookie_salt, &data, &digest_buf)?;

    // Has the expiry time been reached?
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("couldn't get system time")
        .as_secs();

    let mut ts_buf: [u8; 8] = [0; 8];
    for (a, b) in ts_buf.iter_mut().zip(parts_bytes[0].iter()) {
        *a = *b;
    }

    // We must have at least 30 seconds left to parse the cookie
    if now > u64::from_be_bytes(ts_buf) - 30 {
        return Err(Error::InvalidLoginCookie("cookie has expired"));
    }

    // Decode the flags
    let mut flag_buf: [u8; 8] = [0; 8];
    for (a, b) in flag_buf.iter_mut().zip(parts_bytes[2].iter()) {
        *a = *b;
    }
    let flags: LoginFlags = u64::from_be_bytes(flag_buf);

    Ok(LoginId {
        user_id: parts[2],
        flags,
    })
}

// new_login_token will create a new url_b64 encoded login token
pub fn new_login_token(
    login_token_salt: &[u8; 32],
    user_id: &str,
    flags: LoginFlags,
    valid_time: time::Duration,
    nonce: &[u8; 8],
) -> Result<String> {
    let user_id = hex::decode(user_id)
        .map_err(|_| Error::InvalidUserId("not a hexstring"))
        .and_then(|uid| {
            if uid.len() == 16 {
                let mut u: [u8; 16] = [0; 16];
                for (a, b) in u.iter_mut().zip(uid.into_iter()) {
                    *a = b;
                }
                Ok(u)
            } else {
                Err(Error::UserIdWrongLength)
            }
        })?;

    // valid time
    let end_time = time::SystemTime::now()
        .add(valid_time)
        .duration_since(time::UNIX_EPOCH)
        .expect("couldn't compute system time")
        .as_secs()
        .to_be_bytes();

    // 0 is Version
    let mut token = vec![0];

    // Nonce
    token.extend(nonce);

    token.extend(&end_time);
    token.extend(&user_id);
    token.extend(&flags.to_be_bytes());

    let mut digest: [u8; 16] = [0; 16];
    compute_digest(&token, &mut digest, login_token_salt);

    token.extend(&digest);

    let mut encoded_token = String::new();
    base64_url::encode_to_string(&token, &mut encoded_token);

    Ok(encoded_token)
}

fn compute_digest(data: &[u8], digest: &mut [u8; 16], salt: &[u8; 32]) {
    let hash = hmac_sha256::HMAC::mac(data, &salt[..]);

    for (a, b) in digest.iter_mut().zip(md5::compute(hash).into_iter()) {
        *a = b;
    }
}

fn check_digest_match(salt: &[u8; 32], data: &[u8], digest: &[u8; 16]) -> Result<()> {
    let hash = hmac_sha256::HMAC::mac(data, &salt[..]);
    if &md5::compute(hash)[..] == digest {
        Ok(())
    } else {
        Err(Error::BadDigest)
    }
}

fn parse_login_token(
    login_token_salt: &[u8; 32],
    user_token: &str,
) -> Result<([u8; 16], LoginFlags)> {
    let mut token = vec![];
    base64_url::decode_to_vec(user_token, &mut token)
        .map_err(|_| Error::InvalidLoginToken("not base64-url"))?;

    // The first byte is version
    if token[0] != 0 {
        return Err(Error::InvalidLoginToken("not version 0 "));
    }

    if token.len() != 57 {
        return Err(Error::InvalidLoginToken("wrong length"));
    }

    let ts = &token[9..17];
    let user_id = &token[17..33];
    let flags = &token[33..41];
    let mut digest: [u8; 16] = [0; 16];
    for (a, b) in digest.iter_mut().zip(&token[41..]) {
        *a = *b;
    }

    // First check the digest
    check_digest_match(login_token_salt, &token[..41], &digest)?;

    // Check the timestamp
    let mut u64_buf: [u8; 8] = [0; 8];
    for (a, b) in u64_buf.iter_mut().zip(ts) {
        *a = *b;
    }
    let ts = u64::from_be_bytes(u64_buf);

    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("couldn't get system time")
        .as_secs();

    // We must have at least 30 seconds left in the token
    if now > ts - 30 {
        return Err(Error::LoginTokenExpired);
    }

    // Okay - parse the flags
    let mut u64_buf: [u8; 8] = [0; 8];
    for (a, b) in u64_buf.iter_mut().zip(flags) {
        *a = *b;
    }
    let flags: LoginFlags = u64::from_be_bytes(u64_buf);

    // UserId
    let mut user_id_buf: [u8; 16] = [0; 16];
    for (a, b) in user_id_buf.iter_mut().zip(user_id) {
        *a = *b;
    }
    Ok((user_id_buf, flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie() {
        let mut rng = FastRng::new();
        let salt: [u8; 32] = rng.gen();
        let cookie = new_session_cookie(&salt);
        assert_eq!(cookie.len(), 65);
        for (n, hexstring) in cookie.split('-').enumerate() {
            if n != 0 && n != 1 {
                assert!(false);
            }
            assert_eq!(hexstring.len(), 32);
            assert!(hex::decode(hexstring).is_ok());
        }
        // decode the cookie
        let session_id = parse_session_cookie(&salt, &cookie).expect("couldn't get session_id");

        assert_eq!(session_id.len(), 32);
        assert!(hex::decode(&session_id).is_ok());
    }

    #[test]
    fn bad_session_cookie_salt() {
        let mut rng = FastRng::new();
        let salt1: [u8; 32] = rng.gen();
        let salt2: [u8; 32] = rng.gen();
        let cookie1 = new_session_cookie(&salt1);
        let cookie2 = new_session_cookie(&salt2);

        assert!(parse_session_cookie(&salt1, &cookie2).is_err());
        assert!(parse_login_cookie(&salt2, &cookie1).is_err());
    }

    #[test]
    fn bad_session_cookie_hexstring() {
        let mut rng = FastRng::new();
        let sig: [u8; 32] = rng.gen();
        let salt: [u8; 32] = rng.gen();
        let session_id_short = hex::encode(rng.gen::<[u8; 31]>());

        let cookie = format!("{}-{}", session_id_short, hex::encode(sig));
        assert!(parse_session_cookie(&salt, &cookie).is_err());

        let cookie = new_session_cookie(&salt).replace("-", "=");
        assert!(parse_session_cookie(&salt, &cookie).is_err());
    }

    #[test]
    fn user_token() {
        let mut rng = FastRng::new();
        let salt: [u8; 32] = rng.gen();
        let user_id: [u8; 16] = rng.gen();

        let user_tk = new_user_token(&salt, &user_id);
        let user_cookie = new_user_cookie(&salt, &user_tk).expect("invalid user token built");

        let parts = user_cookie.split('-').collect::<Vec<&str>>();
        let user_id_hex = parts[0];

        assert_eq!(hex::encode(&user_id), user_id_hex);

        let user_id_str = parse_user_cookie(&salt, &user_cookie).expect("invalid user cookie");

        assert_eq!(user_id_hex, user_id_str);
    }

    #[test]
    fn login_token() {
        let mut rng = FastRng::new();
        let salt: [u8; 32] = rng.gen();
        let user_id = hex::encode(rng.gen::<[u8; 16]>());
        let nonce: [u8; 8] = rng.gen();
        let flags: LoginFlags = 0;

        let login_tk = new_login_token(
            &salt,
            &user_id,
            flags,
            time::Duration::from_secs(3600),
            &nonce,
        )
        .expect("couldn't create user token");

        let (user_id1, flags1) =
            parse_login_token(&salt, &login_tk).expect("couldn't parse user token");

        assert_eq!(user_id, hex::encode(user_id1));
        assert_eq!(flags, flags1);
    }

    #[test]
    fn login_token_expired() {
        let mut rng = FastRng::new();
        let salt: [u8; 32] = rng.gen();
        let user_id = hex::encode(rng.gen::<[u8; 16]>());
        let nonce: [u8; 8] = rng.gen();
        let flags: LoginFlags = 0;

        let login_tk = new_login_token(
            &salt,
            &user_id,
            flags,
            // expire in 15 seconds - we must have at least 30
            time::Duration::from_secs(15),
            &nonce,
        )
        .expect("couldn't create user token");

        assert!(parse_login_token(&salt, &login_tk).is_err());
    }

    #[test]
    fn login_token_wrong_salt() {
        let mut rng = FastRng::new();
        let salt: [u8; 32] = rng.gen();
        let user_id = hex::encode(rng.gen::<[u8; 16]>());
        let nonce: [u8; 8] = rng.gen();
        let flags: LoginFlags = 0;

        let login_tk = new_login_token(
            &salt,
            &user_id,
            flags,
            // expire in 15 seconds - we must have at least 30
            time::Duration::from_secs(15),
            &nonce,
        )
        .expect("couldn't create user token");

        assert!(parse_login_token(&rng.gen::<[u8; 32]>(), &login_tk).is_err());
    }

    #[test]
    fn login_cookie() {
        let mut rng = FastRng::new();
        let user_id: [u8; 16] = rng.gen();
        let salt: [u8; 32] = rng.gen();
        let flags: LoginFlags = 0;

        let cookie = create_login_cookie(&salt, &user_id, flags, time::Duration::from_secs(3600));
        let login_id = parse_login_cookie(&salt, &cookie).expect("couldn't parse login cookie");
        assert_eq!(login_id.user_id, hex::encode(user_id));
        assert_eq!(login_id.flags, flags);
    }

    #[test]
    fn login_cookie_wrong_salt() {
        let mut rng = FastRng::new();
        let user_id: [u8; 16] = rng.gen();
        let salt: [u8; 32] = rng.gen();
        let flags: LoginFlags = 0;

        let cookie = create_login_cookie(&salt, &user_id, flags, time::Duration::from_secs(3600));
        assert!(parse_login_cookie(&rng.gen(), &cookie).is_err());
    }

    #[test]
    fn login_cookie_expired() {
        let mut rng = FastRng::new();
        let user_id: [u8; 16] = rng.gen();
        let salt: [u8; 32] = rng.gen();
        let flags: LoginFlags = 0;

        // We must have at least thirty seconds left, so 15 is wrong
        let cookie = create_login_cookie(&salt, &user_id, flags, time::Duration::from_secs(15));
        assert!(parse_login_cookie(&salt, &cookie).is_err());
    }
}
