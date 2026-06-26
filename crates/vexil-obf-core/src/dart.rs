use rand_core::{OsRng, RngCore};

use crate::error::ObfError;

pub fn obfuscate_dart(source: &str) -> Result<String, ObfError> {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);

    let (new_source, _encrypted_strings) = encrypt_dart_strings(source, &key);

    let key_arr = key
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let helper = format!(
        "\nList<int> _vdk=[{key_arr}];\n\
         String _vd(List<int> b)=>String.fromCharCodes(\
         b.asMap().map((i,x)=>MapEntry(i,x^_vdk[i%_vdk.length])).values);\n",
        key_arr = key_arr,
    );

    Ok(new_source + &helper)
}

fn encrypt_dart_strings(source: &str, key: &[u8; 16]) -> (String, Vec<Vec<u8>>) {
    let mut out = String::new();
    let mut strings = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // Detect raw strings: r'...' or r"..."  — leave as-is
        if c == 'r' && i + 1 < chars.len() && (chars[i + 1] == '\'' || chars[i + 1] == '"') {
            let quote = chars[i + 1];
            out.push(c);
            out.push(quote);
            i += 2;
            while i < chars.len() && chars[i] != quote {
                out.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                out.push(chars[i]); // closing quote
                i += 1;
            }
            continue;
        }

        // Detect triple-quoted strings: ''' or """  — leave as-is
        if (c == '\'' || c == '"') && i + 2 < chars.len() && chars[i + 1] == c && chars[i + 2] == c
        {
            let quote = c;
            out.push(c);
            out.push(c);
            out.push(c);
            i += 3;
            while i + 2 < chars.len()
                && !(chars[i] == quote && chars[i + 1] == quote && chars[i + 2] == quote)
            {
                out.push(chars[i]);
                i += 1;
            }
            if i + 2 < chars.len() {
                out.push(chars[i]);
                out.push(chars[i + 1]);
                out.push(chars[i + 2]);
                i += 3;
            }
            continue;
        }

        // Single or double quoted strings
        if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != quote {
                if chars[i] == '\\' {
                    i += 1;
                    if i < chars.len() {
                        match chars[i] {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            '$' => s.push('$'),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                    }
                } else {
                    s.push(chars[i]);
                }
                i += 1;
            }
            if i < chars.len() {
                i += 1; // closing quote
            }
            let bytes = s.as_bytes();
            let enc: Vec<u8> = bytes
                .iter()
                .enumerate()
                .map(|(j, b)| b ^ key[j % 16])
                .collect();
            let arr = enc
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("_vd([{}])", arr));
            strings.push(enc);
        } else {
            out.push(c);
            i += 1;
        }
    }

    (out, strings)
}
