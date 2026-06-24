// SPDX-License-Identifier: Apache-2.0
//! Cobalt Strike `bof_pack`-format argument packer.
//!
//! Walks a list of CLI-style flag tokens and emits the equivalent
//! byte sequence the BOF will see in its `args` buffer. The flag
//! vocabulary matches the `bof-runner` CLI:
//!
//! ```text
//! --args RAW    raw bytes, no length prefix. For BOFs that
//!               treat `args` as a C string.
//! --zarg STR    `bof_pack "z"` - `[u32 length LE][bytes][NUL]`.
//! --iarg N      `bof_pack "i"` - `[u32 BE]` (network byte order).
//! --sarg N      `bof_pack "s"` - `[u16 BE]`.
//! --barg @FILE  `bof_pack "b"` - `[u32 length LE][bytes]`.
//! ```
//!
//! Order on the input list determines order in the output buffer -
//! the BOF reads with `BeaconDataExtract` / `BeaconDataInt` etc. in
//! matching order. Mixing typed flags with `--args` is supported but
//! rare; `--args`'s raw bytes go first.

pub fn parse_packed_args(args: &[String]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let take_value = || -> Result<&str, String> {
            args.get(i + 1).map(|s| s.as_str())
                .ok_or_else(|| format!("`{flag}` requires a value"))
        };
        match flag {
            "--args" => {
                // Raw bytes - appended as-is, NO length prefix. A BOF
                // reading this with BeaconDataExtract won't find the
                // expected `[u32 len][bytes]` shape - `--args` is the
                // "treat args buffer as a C string" path.
                let v = take_value()?;
                out.extend_from_slice(v.as_bytes());
                i += 2;
            }
            "--zarg" => {
                let v = take_value()?;
                let bytes = v.as_bytes();
                let length = (bytes.len() + 1) as u32;
                out.extend_from_slice(&length.to_le_bytes());
                out.extend_from_slice(bytes);
                out.push(0);
                i += 2;
            }
            "--iarg" => {
                let v = take_value()?;
                let n: i32 = v.parse()
                    .map_err(|e| format!("--iarg `{v}`: {e}"))?;
                out.extend_from_slice(&n.to_be_bytes());
                i += 2;
            }
            "--sarg" => {
                let v = take_value()?;
                let n: i16 = v.parse()
                    .map_err(|e| format!("--sarg `{v}`: {e}"))?;
                out.extend_from_slice(&n.to_be_bytes());
                i += 2;
            }
            "--barg" => {
                let v = take_value()?;
                let Some(path) = v.strip_prefix('@') else {
                    return Err(format!("--barg expects `@path` (got `{v}`)"));
                };
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("--barg {path}: {e}"))?;
                let length = bytes.len() as u32;
                out.extend_from_slice(&length.to_le_bytes());
                out.extend_from_slice(&bytes);
                i += 2;
            }
            other => return Err(format!("unknown flag: `{other}`")),
        }
    }
    Ok(out)
}
