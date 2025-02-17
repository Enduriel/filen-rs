use core::str;
use std::{cell::RefCell, str::FromStr};

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use generic_array::typenum::U12;
use pbkdf2::hmac::Hmac;
use rsa::{
	pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
	pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha512};

const NONCE_VALUES: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn make_insecure_nonce() -> Result<Nonce<generic_array::typenum::U12>> {
	let mut buf = [0u8; 12];
	getrandom::fill(&mut buf).map_err(|e| anyhow!("Failed to generate nonce: {:?}", e))?;
	buf.iter_mut()
		.for_each(|byte| *byte = NONCE_VALUES[(*byte % NONCE_VALUES.len() as u8) as usize]);
	Ok(buf.into())
}

#[derive(Serialize, Debug)]
pub struct DerivedPassword(pub String);

pub fn generate_password_and_master_key(
	raw_password: &str,
	auth_version: u32,
	salt: &str,
) -> Result<(DerivedPassword, MasterKey)> {
	if auth_version != 2 {
		return Err(anyhow::anyhow!("Unsupported auth version"));
	}

	let mut buf = [0u8; 64];
	pbkdf2::pbkdf2::<Hmac<Sha512>>(raw_password.as_bytes(), salt.as_bytes(), 200_000, &mut buf)?;
	let (master_key, password) = buf.split_at(32);
	let mut hasher = Sha512::new();
	// This is how Filen does it in the TS sdk.
	// Is it annoying to have to convert to a string and back? Yes.
	let password = hex::encode(password);
	hasher.update(password.as_bytes());
	let password = hex::encode(hasher.finalize());
	Ok((
		DerivedPassword(password),
		MasterKey::from_str(&hex::encode(master_key))?,
	))
}

pub trait SymmetricKey: FromStr + AsRef<str> + std::fmt::Debug {
	fn get_cipher(&self) -> &aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12>;

	fn encrypt_split_data(&self, nonce: &Nonce<U12>, data: &mut Vec<u8>) -> Result<()> {
		self.get_cipher()
			.encrypt_in_place(nonce, b"", data)
			.map_err(|e| anyhow!("Encryption failed: {:?}", e))?;
		Ok(())
	}

	fn encrypt_data(&self, data: &mut Vec<u8>) -> Result<()> {
		let nonce = make_insecure_nonce()?;
		self.encrypt_split_data(&nonce, data)?;
		let original_len = data.len();
		data.extend_from_within(original_len - 12..);
		data.copy_within(0..original_len - 12, 12);
		data[..12].copy_from_slice(&nonce);
		Ok(())
	}

	fn decrypt_split_data(&self, nonce: &Nonce<U12>, data: &mut Vec<u8>) -> Result<()> {
		self.get_cipher()
			.decrypt_in_place(nonce, b"", data)
			.map_err(|e| anyhow!("Decryption failed: {:?}", e))?;
		Ok(())
	}

	fn decrypt_data(&self, data: &mut Vec<u8>) -> Result<()> {
		// not super happy with this approach, I think this has an unnecessary allocation
		let nonce = Nonce::clone_from_slice(&data[..12]);
		data.copy_within(12.., 0);
		data.truncate(data.len() - 12);
		self.decrypt_split_data(&nonce, data)?;
		Ok(())
	}
}

pub struct BasicKey<const N: usize> {
	chars: [u8; N],
	cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, generic_array::typenum::U12>,
}

impl<const N: usize> PartialEq for BasicKey<N> {
	fn eq(&self, other: &Self) -> bool {
		self.chars == other.chars
	}
}

impl<const N: usize> std::fmt::Debug for BasicKey<N> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SymmetricKey")
			.field("key", &self.as_ref())
			.finish()
	}
}

impl<'de, const N: usize> Deserialize<'de> for BasicKey<N> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Self::from_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
	}
}

impl<const N: usize> FromStr for BasicKey<N> {
	type Err = anyhow::Error;

	fn from_str(key: &str) -> std::result::Result<Self, Self::Err> {
		let chars = std::convert::TryInto::<[u8; N]>::try_into(key.as_bytes())
			.map_err(|e| anyhow!("Invalid key length for BasicKey {}", e))?;
		// wish I could do this at compile time but const generics are MVP
		let transformed: [u8; 32] = match N {
			32 => unsafe { *(&chars as *const [u8; N] as *const [u8; 32]) }, // SAFETY: being in this branch means N == 32,
			64 => {
				let mut transformed = [0; 32];
				// SAFETY: the key is 32 bytes long and Hmac can be of any length
				pbkdf2::pbkdf2::<Hmac<Sha512>>(
					// the fact that I use the string representation of the key here is confusing
					// but this is how the TS sdk does it
					&chars,
					&chars,
					1,
					&mut transformed,
				)
				.unwrap();
				transformed
			}
			_ => return Err(anyhow!("Unsupported key length")),
		};

		let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&transformed);
		let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(key);

		Ok(Self { chars, cipher })
	}
}

impl<const N: usize> AsRef<str> for BasicKey<N> {
	fn as_ref(&self) -> &str {
		// SAFETY: the key is 64 bytes long and is guaranteed to be valid UTF-8
		unsafe { std::str::from_utf8_unchecked(&self.chars) }
	}
}

impl<const N: usize> SymmetricKey for BasicKey<N> {
	fn get_cipher(&self) -> &aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12> {
		&self.cipher
	}
}

pub struct MasterKey {
	key: BasicKey<64>,
	garbage: RefCell<Vec<u8>>,
}

impl PartialEq for MasterKey {
	fn eq(&self, other: &Self) -> bool {
		self.key == other.key
	}
}

impl std::fmt::Debug for MasterKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MasterKey")
			.field("key", &self.as_ref())
			.finish()
	}
}

impl AsRef<str> for MasterKey {
	fn as_ref(&self) -> &str {
		self.key.as_ref()
	}
}

impl SymmetricKey for MasterKey {
	fn get_cipher(&self) -> &aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12> {
		self.key.get_cipher()
	}
}

impl MasterKey {
	pub fn encrypt_metadata(&self, metadata: &str, out_string: &mut String) -> Result<()> {
		out_string.clear();
		out_string.push_str("002");
		let mut garbage = self.garbage.borrow_mut();
		garbage.clear();
		garbage.extend_from_slice(metadata.as_bytes());
		let nonce = make_insecure_nonce()?;
		self.encrypt_split_data(&nonce, &mut garbage)?;
		// SAFETY: the nonce is made up of valid ASCII characters in make_insecure_nonce
		out_string.push_str(unsafe { core::str::from_utf8_unchecked(&nonce) });
		BASE64_STANDARD.encode_string(&*garbage, out_string);
		Ok(())
	}

	pub fn decrypt_metadata(
		&self,
		encrypted_metadata: &str,
		out_string: &mut String,
	) -> Result<()> {
		match (
			encrypted_metadata.get(0..3),
			encrypted_metadata.get(3..15),
			encrypted_metadata.get(15..),
		) {
			(Some("002"), Some(nonce), Some(encrypted)) => {
				out_string.clear();
				let mut garbage = self.garbage.borrow_mut();
				garbage.clear();
				BASE64_STANDARD.decode_vec(encrypted, &mut garbage)?;
				let nonce = Nonce::from_slice(nonce.as_bytes());
				self.decrypt_split_data(nonce, &mut garbage)?;
				out_string.push_str(core::str::from_utf8(&garbage)?);
				Ok(())
			}
			(Some(v), _, _) => Err(anyhow!("Unsupported metadata version: {}", v)),
			_ => Err(anyhow!("Invalid metadata")),
		}
	}
}

impl FromStr for MasterKey {
	type Err = anyhow::Error;

	fn from_str(key: &str) -> Result<Self> {
		Ok(Self {
			key: BasicKey::from_str(key)?,
			garbage: RefCell::new(Vec::new()),
		})
	}
}

pub struct MasterKeys {
	pub keys: Vec<MasterKey>,
}

impl MasterKeys {
	pub fn new(first_key: MasterKey, encrypted_master_key_str: &str) -> Result<Self> {
		let mut decrypted_master_key_str = String::new();
		first_key.decrypt_metadata(encrypted_master_key_str, &mut decrypted_master_key_str)?;
		let mut keys = decrypted_master_key_str
			.split('|')
			.map(MasterKey::from_str)
			.filter(|key| match key {
				Ok(some) => *some != first_key,
				_ => true,
			})
			.collect::<Result<Vec<_>>>()?;
		keys.insert(0, first_key); // not the most efficient, but simple
		Ok(Self { keys })
	}

	pub fn decrypt_metadata(
		&self,
		encrypted_metadata: &str,
		out_string: &mut String,
	) -> Result<()> {
		for key in &self.keys {
			if key.decrypt_metadata(encrypted_metadata, out_string).is_ok() {
				return Ok(());
			}
		}
		Err(anyhow!("Failed to decrypt metadata"))
	}

	pub fn decrypt_data(&self, data: &mut Vec<u8>) -> Result<()> {
		for key in &self.keys {
			if key.decrypt_data(data).is_ok() {
				return Ok(());
			}
		}
		Err(anyhow!("Failed to decrypt data"))
	}
}

pub struct RSAKeyPair {
	private_key: rsa::RsaPrivateKey,
	public_key: rsa::RsaPublicKey,
}

impl RSAKeyPair {
	pub fn from_strings(
		first_key: &MasterKeys,
		encrypted_private_key: &str,
		public_key: &str,
	) -> Result<Self> {
		let mut private_key = String::new();
		first_key.decrypt_metadata(encrypted_private_key, &mut private_key)?;
		Ok(Self {
			private_key: rsa::RsaPrivateKey::from_pkcs8_der(&BASE64_STANDARD.decode(private_key)?)?,
			public_key: rsa::RsaPublicKey::from_public_key_der(
				&BASE64_STANDARD.decode(public_key)?,
			)?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decrypt_master_keys() {
		let master_keys_text = "002sOU8EApvwmaZT6iWIlZSqdoWX2iLJ8dXX2nrKhsgYLQBwtdR6JAy9q37+emTfFN8cDgUkjGAm3Vwgugo8xvs9wNCosZydo73YQ8AS5DpCdvJeRtFfRLwFj9KwkEIOehVNH1FsOfRpxHxjHFzfRiQ//DANl3id9bPHzXZUnJBeIEyaKdOKDIxos0KwVCCvTnQq45tqmhIpLRyICzIL/AbQc0s7gFaScQvPP9lOVerWWx0pahl+9h7ODibOEQwhNuEYTtLLy5P5JZjaKmCaKAXRmJs8RRMksWzM79F";
		let master_key =
			MasterKey::from_str("ba8409ed0356864c08237f55bbeb4307869b03633cfa59219849d5b316abb06b")
				.unwrap();
		// let mut decrypted = String::new();
		// master_key
		// 	.decrypt_metadata(master_keys_text, &mut decrypted)
		// 	.unwrap();

		assert_eq!(
			MasterKeys::new(master_key, master_keys_text)
				.unwrap()
				.keys
				.iter()
				.map(MasterKey::as_ref)
				.collect::<Vec<_>>(),
			[
				"ba8409ed0356864c08237f55bbeb4307869b03633cfa59219849d5b316abb06b",
				"cf6515ed9c16043e9a4003f08e4d782a0f6b1105aa3efb84438fde0536b21b06",
				"39fb89143e9c2b7841e2f061895fd4a2b8fdb602fef25df865935c1c82f0d3c4",
			]
		);
	}

	#[test]
	fn encrypt_decrypt_meta() {
		let master_key =
			MasterKey::from_str("ba8409ed0356864c08237f55bbeb4307869b03633cfa59219849d5b316abb06b")
				.unwrap();
		let original = "test";
		let mut encrypted_meta = String::new();
		master_key
			.encrypt_metadata(original, &mut encrypted_meta)
			.unwrap();
		let mut decrypted_meta = String::new();
		master_key
			.decrypt_metadata(&encrypted_meta, &mut decrypted_meta)
			.unwrap();
		assert_eq!(original, decrypted_meta);
	}
}
