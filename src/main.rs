use base64::Engine;
use bytes::Buf;
use cookie_store::{Cookie, CookieStore};
use digest::Digest;
use hmac::Mac;
use ureq::Agent;
use url::Url;

static UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                   AppleWebKit/537.36 (KHTML, like Gecko) \
                   Chrome/80.0.3987.149 Safari/537.36";
static SYSNAME: &str = "Windows";

#[derive(serde::Deserialize, serde::Serialize)]
struct UsernamePassword {
    username: String,
    password: String,
}
static DEFAULT_ENV_FILE: &str = "account.json";

fn main() {
    let mut opts = getopts::Options::new();
    opts.optflag("x", "logout", "Log out (default behaviour is log in)");
    opts.optflag("h", "help", "Print this help menu");
    opts.optopt(
        "f",
        "env-file",
        "Specify the file containing username and password",
        "FILE",
    );
    let matches = opts.parse(std::env::args()).unwrap();

    if matches.opt_present("h") {
        println!(
            "{}",
            opts.usage(
                "Usage: beihang-login [options]\n\
                \n\
                You should write your username and password as {\"username\": ..., \"password\": ...}\n\
                in a JSON file named `account.json` in the working directory, or supply it with `-f`.\n\
                A account.json.example is distributed with this file."
            )
        );
        return;
    }

    let is_logout = matches.opt_present("x");
    let env_file = matches
        .opt_str("f")
        .unwrap_or_else(|| DEFAULT_ENV_FILE.to_owned());

    let env_file = match std::fs::File::open(&env_file) {
        Ok(f) => f,
        Err(err) => {
            panic!(
                "Unable to open the env file located at {}: {}",
                env_file, err
            )
        }
    };
    let env: UsernamePassword = serde_json::from_reader(env_file).unwrap_or_else(|err| {
        panic!("Unable to parse the env file: {}", err)
    });

    /*
    pgv_pvi=2381688832; AD_VALUE=8751256e; cookie=0; lang=zh-CN; user=$USERNAME */
    let url = "https://gw.buaa.edu.cn/index_1.html"
        .parse::<Url>()
        .unwrap();

    let mut cookies = CookieStore::new(None);
    cookies
        .insert(Cookie::parse("pgv_pvi=2381688832", &url).unwrap(), &url)
        .unwrap();
    cookies
        .insert(Cookie::parse("AD_VALUE=8751256e", &url).unwrap(), &url)
        .unwrap();
    cookies
        .insert(Cookie::parse("cookie=0", &url).unwrap(), &url)
        .unwrap();
    cookies
        .insert(Cookie::parse("lang=zh-CN", &url).unwrap(), &url)
        .unwrap();
    cookies
        .insert(
            Cookie::parse(format!("user={}", env.username), &url).unwrap(),
            &url,
        )
        .unwrap();

    let mut client = ureq::AgentBuilder::new()
        .cookie_store(cookies)
        .user_agent(UA);
    #[cfg(feature = "native-tls")]
    {
        client = client.tls_connector(Arc::new(native_tls::TlsConnector::new().unwrap()))
    }
    let client = client.build();
    /*
        RESULT=`curl -k -s -c $COOKIEFILE \
    --noproxy '*' \
    -H 'Host: gw.buaa.edu.cn' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'User-Agent: $UA' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-User: ?1' \
    -H 'DNT: 1' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8,application/signed-exchange;v=b3' \
    -H 'Purpose: prefetch' \
    -H 'Sec-Fetch-Site: none' \
    -H 'Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6' \
    -H 'Cookie: pgv_pvi=2381688832; AD_VALUE=8751256e; cookie=0; lang=zh-CN; user=$USERNAME' \
    'https://gw.buaa.edu.cn/index_1.html?ad_check=1'`
     */
    let result = client
        .get("https://gw.buaa.edu.cn/index_1.html?ad_check=1")
        .set("Host", "gw.buaa.edu.cn")
        .set("Upgrade-Insecure-Requests", "1")
        .set("Sec-Fetch-Mode", "navigate")
        .set("Sec-Fetch-User", "?1")
        .set("DNT", "1")
        .set(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\
             image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        )
        .set("Purpose", "prefetch")
        .set("Sec-Fetch-Site", "none")
        .set(
            "Accept-Language",
            "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6",
        )
        .call()
        .unwrap();

    /*
    #echo $RESULT
    AC_ID=${RESULT#*ac_id=}
    AC_ID=1
    echo "AC_ID: "$AC_ID */
    let ac_id: u32 = result
        .get_url()
        .split("ac_id=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(67);

    /*# Get challenge number
    RESULT=`curl -k -s -b $COOKIEFILE \
    --noproxy '*' \
    -H "Host: gw.buaa.edu.cn" \
    -H "Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, *//*; q=0.01" \
    -H "DNT: 1" \
    -H "X-Requested-With: XMLHttpRequest" \
    -H "User-Agent: $UA" \
    -H "Sec-Fetch-Mode: cors" \
    -H "Sec-Fetch-Site: same-origin" \
    -H "Referer: https://gw.buaa.edu.cn/srun_portal_pc?ac_id=$AC_ID&theme=buaa&url=www.buaa.edu.cn" \
    -H "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6" \
    "https://gw.buaa.edu.cn/cgi-bin/get_challenge?callback=jQuery112407419864172676014_1566720734115&username="$USERNAME"&ip="$IPADDR"&_="$TIMESTAMP`
     */
    let timestamp = chrono::Utc::now().timestamp_millis();
    let result = client
        .get("https://gw.buaa.edu.cn/cgi-bin/get_challenge")
        .set("Host", "gw.buaa.edu.cn")
        .set(
            "Accept",
            "text/javascript, application/javascript, application/ecmascript, \
             application/x-ecmascript, */*; q=0.01",
        )
        .set("DNT", "1")
        .set("X-Requested-With", "XMLHttpRequest")
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Site", "same-origin")
        .set(
            "Referer",
            &format!(
                "https://gw.buaa.edu.cn/srun_portal_pc?ac_id={}&theme=buaa&url=www.buaa.edu.cn",
                ac_id
            ),
        )
        .set(
            "Accept-Language",
            "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6",
        )
        .query_pairs([
            ("callback", "jQuery112407419864172676014_1566720734115"),
            ("username", env.username.as_str()),
            ("ip", ""),
            ("_", &timestamp.to_string()),
        ])
        .call()
        .unwrap();

    /*
        # A dirty way to obtain information in JSON string.
    CHALLENGE=`echo $RESULT | cut -d '"' -f4`
    CLIENTIP=`echo $RESULT | cut -d '"' -f8`
    echo "Challenge: "$CHALLENGE
    echo "Client IP: "$CLIENTIP */
    let result = result.into_string().unwrap();
    let challenge = result.split('"').nth(3).unwrap();
    let client_ip = result.split('"').nth(7).unwrap();

    println!("Challenge: {}", challenge);
    println!("Client IP: {}", client_ip);

    if !is_logout {
        login(&client, &env, ac_id, challenge, client_ip, timestamp);
    } else {
        logout(&client, &env, ac_id, client_ip);
    }
}

fn login(
    client: &Agent,
    env: &UsernamePassword,
    ac_id: u32,
    challenge: &str,
    client_ip: &str,
    timestamp: i64,
) {
    /*
    if [[ "$option" == "login" ]]; then
    # The password is hashed using HMAC-MD5.
    ENCRYPT_PWD=`echo -n $PASSWORD | openssl md5 -hmac $CHALLENGE`
    # Remove the possible "(stdin)= " prefix
    ENCRYPT_PWD=${ENCRYPT_PWD#*= }
    PWD=$ENCRYPT_PWD
    echo "Encrypted PWD: "$PWD*/

    let mut hmac_md5 = hmac::Hmac::<md5::Md5>::new_from_slice(challenge.as_bytes()).unwrap();
    hmac_md5.update(env.password.as_bytes());
    let encrypt_pwd = hmac_md5.finalize().into_bytes();
    let pwd = hex::encode(encrypt_pwd);
    println!("Encrypted PWD: {}", pwd);

    /* # Some info is encrypted using srun_bx1 and base64 and substitution ciper
    INFO='{"username":"'$USERNAME'","password":"'$PASSWORD'","ip":"'$CLIENTIP'","acid":"'$AC_ID'","enc_ver":"srun_bx1"}'
    #echo "Info: "$INFO
    ENCRYPT_INFO=$(l_func $INFO $CHALLENGE)
    ENCRYPT_INFO=`echo -ne $ENCRYPT_INFO | openssl enc -base64 -A | tr "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"`
    echo "Encrypted Info: "$ENCRYPT_INFO*/

    let info = format!(
        r#"{{"username":"{}","password":"{}","ip":"{}","acid":"{}","enc_ver":"srun_bx1"}}"#,
        env.username, env.password, client_ip, ac_id
    );
    let encrypt_info = l(info.as_bytes(), challenge.as_bytes());
    let base64_alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
    let base64_alphabet = base64::alphabet::Alphabet::new(base64_alphabet).unwrap();
    let engine = base64::engine::GeneralPurpose::new(&base64_alphabet, Default::default());
    let encrypt_info = engine.encode(encrypt_info);
    println!("Encrypted Info: {}", encrypt_info);

    /*
    # Checksum is calculated using SHA1
    CHKSTR=${CHALLENGE}${USERNAME}${CHALLENGE}${ENCRYPT_PWD}${CHALLENGE}${AC_ID}${CHALLENGE}${CLIENTIP}${CHALLENGE}"200"${CHALLENGE}"1"${CHALLENGE}"{SRBX1}"${ENCRYPT_INFO}
    #echo "Check String: "$CHKSTR
    CHKSUM=`echo -n $CHKSTR | openssl dgst -sha1`
    # Remove the possible "(stdin)= " prefix
    CHKSUM=${CHKSUM#*= }
    echo "Checksum: "$CHKSUM
    */

    let chkstr = format!(
        "{challenge}{username}{challenge}{encrypt_pwd}{challenge}{ac_id}{challenge}{client_ip}{challenge}200{challenge}1{challenge}{{SRBX1}}{encrypt_info}",
        challenge = challenge,
        username = env.username,
        encrypt_pwd = pwd,
        ac_id = ac_id,
        client_ip = client_ip,
        encrypt_info = encrypt_info,
    );
    let mut sha1 = sha1::Sha1::default();
    sha1.update(chkstr.as_bytes());
    let chksum = sha1.finalize();
    let chksum = hex::encode(chksum);
    println!("Checksum: {}", chksum);

    /*
    # URLEncode the "+", "=", "/" in encrypted info.
    URL_INFO=$(echo -n $ENCRYPT_INFO | sed "s/\//%2F/g" | sed "s/=/%3D/g" | sed "s/+/%2B/g")
    #echo "URL Info: "$URL_INFO*/

    /*

       # Submit data and login
       curl -k -b $COOKIEFILE \
           --noproxy '*' \
       -H "Host: gw.buaa.edu.cn" \
       -H "Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, *//*; q=0.01" \
       -H "DNT: 1" \
       -H "X-Requested-With: XMLHttpRequest" \
       -H "User-Agent: $UA" \
       -H "Sec-Fetch-Mode: cors" \
       -H "Sec-Fetch-Site: same-origin" \
       -H "Referer: https://gw.buaa.edu.cn/srun_portal_pc?ac_id=$AC_ID&theme=buaa&url=www.buaa.edu.cn" \
       -H "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6" \
       "https://gw.buaa.edu.cn/cgi-bin/srun_portal?callback=jQuery112407419864172676014_1566720734115&action=login&username="$USERNAME"&password=%7BMD5%7D"$PWD"&ac_id=$AC_ID&ip="$CLIENTIP"&chksum="$CHKSUM"&info=%7BSRBX1%7D"$URL_INFO"&n=200&type=1&os="$SYSNAME"&name=Macintosh&double_stack=0&_="$TIMESTAMP
    */

    let resp = client
        .post("https://gw.buaa.edu.cn/cgi-bin/srun_portal")
        .set("Host", "gw.buaa.edu.cn")
        .set(
            "Accept",
            "text/javascript, application/javascript, application/ecmascript, \
             application/x-ecmascript, */*; q=0.01",
        )
        .set("DNT", "1")
        .set("X-Requested-With", "XMLHttpRequest")
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Site", "same-origin")
        .set(
            "Referer",
            &format!(
                "https://gw.buaa.edu.cn/srun_portal_pc?ac_id={}&theme=buaa&url=www.buaa.edu.cn",
                ac_id
            ),
        )
        .set(
            "Accept-Language",
            "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6",
        )
        .query_pairs([
            ("callback", "jQuery112407419864172676014_1566720734115"),
            ("action", "login"),
            ("username", env.username.as_str()),
            ("password", &format!("{{MD5}}{}", pwd)),
            ("ac_id", &ac_id.to_string()),
            ("ip", client_ip),
            ("chksum", &chksum),
            ("info", &format!("{{SRBX1}}{}", encrypt_info)),
            ("n", "200"),
            ("type", "1"),
            ("os", SYSNAME),
            ("name", "Macintosh"),
            ("double_stack", "0"),
            ("_", &timestamp.to_string()),
        ])
        .call()
        .unwrap();

    println!("Response: {:?}", resp.into_string().unwrap());
}

fn logout(client: &Agent, env: &UsernamePassword, ac_id: u32, client_ip: &str) {
    /*
       curl -k -b $COOKIEFILE \
           --noproxy '*' \
       -H "Host: gw.buaa.edu.cn" \
       -H "Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, *//*; q=0.01" \
       -H "DNT: 1" \
       -H "X-Requested-With: XMLHttpRequest" \
       -H "User-Agent: $UA" \
       -H "Sec-Fetch-Mode: cors" \
       -H "Sec-Fetch-Site: same-origin" \
       -H "Referer: https://gw.buaa.edu.cn/srun_portal_pc?ac_id=$AC_ID&theme=buaa&url=www.buaa.edu.cn" \
       -H "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6" \
       "https://gw.buaa.edu.cn/cgi-bin/srun_portal?callback=jQuery112407419864172676014_1566720734115&action=logout&username="$USERNAME"&ac_id=$AC_ID&ip="$CLIENTIP
    */

    let resp = client
        .post("https://gw.buaa.edu.cn/cgi-bin/srun_portal")
        .set("Host", "gw.buaa.edu.cn")
        .set(
            "Accept",
            "text/javascript, application/javascript, application/ecmascript, \
             application/x-ecmascript, */*; q=0.01",
        )
        .set("DNT", "1")
        .set("X-Requested-With", "XMLHttpRequest")
        .set("Sec-Fetch-Mode", "cors")
        .set("Sec-Fetch-Site", "same-origin")
        .set(
            "Referer",
            &format!(
                "https://gw.buaa.edu.cn/srun_portal_pc?ac_id={}&theme=buaa&url=www.buaa.edu.cn",
                ac_id
            ),
        )
        .set(
            "Accept-Language",
            "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6",
        )
        .query_pairs([
            ("callback", "jQuery112407419864172676014_1566720734115"),
            ("action", "logout"),
            ("username", env.username.as_str()),
            ("ac_id", &ac_id.to_string()),
            ("ip", client_ip),
        ])
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    println!("Response: {:?}", resp);
}

fn s(mut a: &[u8], append_len: bool) -> Vec<u32> {
    let len_a = a.len();
    let mut v = vec![];
    while a.len() >= 4 {
        v.push(a.get_u32_le());
    }
    // push the last 0-4 bytes and pad with 0
    let mut c = 0;
    for i in 0..4 {
        if i < a.len() {
            c |= (a[i] as u32) << (i * 8);
        }
    }
    if !a.is_empty() {
        v.push(c);
    }

    if append_len {
        v.push(len_a as u32);
    }
    v
}

fn x_encode(str: &[u8], challenge: &[u8]) -> Vec<u32> {
    let mut v = s(str, true);
    let mut k = s(challenge, false);
    while k.len() < 4 {
        k.push(0);
    }

    /*
    D
          return l(v, false); */

    let n = v.len() - 1;
    let mut z = v[n];
    let mut y;
    let c = 0x86014019 | 0x183639A0;
    let mut m;
    let mut e;
    let mut p: u32;
    let mut q = (6. + 52. / (n as f64 + 1.0)) as usize;
    let mut d: u32 = 0;

    while q > 0 {
        d = d.wrapping_add(c);
        e = d >> 2 & 3;
        for p in 0..n {
            y = v[p + 1];
            m = z >> 5 ^ y << 2;
            m = m.wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y));
            m = m.wrapping_add(k[((p as u32 & 3) ^ e) as usize] ^ z);
            v[p] = v[p].wrapping_add(m);
            z = v[p];
        }
        p = n as u32;
        y = v[0];
        m = z >> 5 ^ y << 2;
        m = m.wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y));
        m = m.wrapping_add(k[((p & 3) ^ e) as usize] ^ z);
        v[n] = v[n].wrapping_add(m);
        z = v[n];

        q -= 1;
    }

    v
}

fn l(str: &[u8], key: &[u8]) -> Vec<u8> {
    let a = x_encode(str, key);
    let d = a.len();
    let mut v = vec![];
    for i in 0..d {
        let code1 = a[i] & 255;
        let code2 = (a[i] >> 8) & 255;
        let code3 = (a[i] >> 16) & 255;
        let code4 = (a[i] >> 24) & 255;
        v.push(code1 as u8);
        v.push(code2 as u8);
        v.push(code3 as u8);
        v.push(code4 as u8);
    }
    v
}
