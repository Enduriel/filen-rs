use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(bound = "T: Deserialize<'de>")]
pub struct FilenResponse<T>
where
	T: std::fmt::Debug,
{
	pub status: Option<bool>,
	pub message: Option<String>,
	pub code: Option<String>,
	data: Option<T>,
}

impl<T> FilenResponse<T>
where
	T: std::fmt::Debug,
{
	pub fn into_data(self) -> Result<T> {
		self.data.ok_or_else(|| {
			anyhow::anyhow!(
				"API Error, message: {:?}, code: {:?}",
				self.message,
				self.code
			)
		})
	}
}

// /v3/auth/info
#[derive(Serialize, Debug)]
pub struct AuthInfoRequest<'a> {
	pub email: &'a str,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfoData {
	pub email: String,
	pub auth_version: u32,
	pub salt: String,
	pub id: u64,
}

// /v3/login
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest<'a> {
	pub email: &'a str,
	pub password: crate::crypto::DerivedPassword,
	pub two_factor_code: &'a str,
	pub auth_version: u32,
}

impl<'a> LoginRequest<'a> {
	pub fn new(
		email: &'a str,
		password: crate::crypto::DerivedPassword,
		two_factor_code: &'a str,
	) -> Self {
		Self {
			email,
			password,
			two_factor_code,
			auth_version: 2,
		}
	}

	pub fn new_no_2fa(email: &'a str, password: crate::crypto::DerivedPassword) -> Self {
		Self::new(email, password, "XXXXXX")
	}
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
	pub api_key: String,
	// this is called masterKeys in the response, despite being a single key
	#[serde(rename = "masterKeys")]
	pub master_key: String,
	pub public_key: String,
	pub private_key: String,
}

// /v3/user/masterKeys
#[derive(Serialize)]
pub struct MasterKeysRequest<'a> {
	#[serde(rename = "masterKeys")]
	pub master_key: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct MasterKeysData {
	pub keys: String,
}
