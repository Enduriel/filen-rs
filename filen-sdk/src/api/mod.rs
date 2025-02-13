use core::str;
use std::{
	io::{Seek, Write},
	os::windows::fs::FileExt,
	process::Child,
};

use anyhow::Result;
use futures::{stream::FuturesUnordered, StreamExt};
use reqwest::RequestBuilder;
use uuid::Uuid;

use crate::{
	crypto::{self, MasterKey, MasterKeys, RSAKeyPair, SymmetricKey},
	fs::{ChildDirectory, Directory, EncryptedChildDirectory, FileInfo, RootDirectory},
};

pub mod types;
use types::*;

pub const FILEN_HOSTS: &[&str] = &[
	"egest.filen.io",
	"egest.filen.net",
	"egest.filen-1.net",
	"egest.filen-2.net",
	"egest.filen-3.net",
	"egest.filen-4.net",
	"egest.filen-5.net",
	"egest.filen-6.net",
];

const CHUNK_SIZE: u64 = 1024 * 1024;

fn build_get_auth_request(
	client: &reqwest::Client,
	url: &str,
	api_key: &str,
) -> reqwest::RequestBuilder {
	client
		.get(url)
		.header("Authorization", format!("Bearer {}", api_key))
}

pub fn build_post_auth_request(
	client: &reqwest::Client,
	url: &str,
	api_key: &str,
) -> reqwest::RequestBuilder {
	client
		.post(url)
		.header("Authorization", format!("Bearer {}", api_key))
}

// TODO handle proper error response

pub trait Unautharized {
	fn get_client(&self) -> &reqwest::Client;

	fn get_auth_info(
		&self,
		request: AuthInfoRequest<'_>,
	) -> impl std::future::Future<Output = Result<AuthInfoData>> {
		async move {
			let response = self
				.get_client()
				.post("https://gateway.filen.io/v3/auth/info")
				.json(&request)
				.send()
				.await?;
			if !response.status().is_success() {
				return Err(anyhow::anyhow!("Failed to get auth info {:?}", response));
			}
			let response: FilenResponse<AuthInfoData> = response.json().await?;
			response.into_data()
		}
	}

	fn raw_login(
		&self,
		request: LoginRequest<'_>,
	) -> impl std::future::Future<Output = Result<LoginData>> {
		async move {
			let response = self
				.get_client()
				.post("https://gateway.filen.io/v3/login")
				.json(&request)
				.send()
				.await?;
			if !response.status().is_success() {
				return Err(anyhow::anyhow!("Failed to login {:?}", response));
			}
			let response: FilenResponse<LoginData> = response.json().await?;
			response.into_data()
		}
	}

	fn login(
		&self,
		password: &str,
		email: &str,
		two_factor_code: &str,
	) -> impl std::future::Future<Output = Result<AuthorizedClient>> {
		async move {
			let salt = self.get_auth_info(AuthInfoRequest { email }).await?.salt;
			let (derived_password, master_key) =
				crypto::generate_password_and_master_key(password, 2, &salt)?;
			let login_request = LoginRequest::new(email, derived_password, two_factor_code);
			let login_data = self.raw_login(login_request).await?;
			AuthorizedClient::new(
				login_data.api_key,
				login_data.private_key,
				login_data.public_key,
				master_key,
			)
			.await
		}
	}
}

#[derive(Default)]
pub struct UnautharizedClient {
	client: reqwest::Client,
}

impl Unautharized for UnautharizedClient {
	fn get_client(&self) -> &reqwest::Client {
		&self.client
	}
}

// consider using secrecy crate for keys here in the future
pub struct AuthorizedClient {
	client: reqwest::Client,
	api_key: String,
	key_pair: RSAKeyPair,
	master_keys: MasterKeys,
}

impl AuthorizedClient {
	pub async fn new(
		api_key: String,
		private_key: String,
		public_key: String,
		master_key: MasterKey,
	) -> Result<Self> {
		let client = reqwest::Client::new();
		let request = build_post_auth_request(
			&client,
			"https://gateway.filen.io/v3/user/masterKeys",
			&api_key,
		)
		.json(&MasterKeysRequest {
			master_key: master_key.as_ref(),
		})
		.send()
		.await?;
		if !request.status().is_success() {
			return Err(anyhow::anyhow!("Failed to get master keys {:?}", request));
		}

		let master_keys_response: FilenResponse<MasterKeysData> = request.json().await?;
		let master_keys = MasterKeys::new(master_key, &master_keys_response.into_data()?.keys)?;

		Ok(Self {
			client,
			api_key,
			key_pair: RSAKeyPair::from_strings(&master_keys, &private_key, &public_key)?,
			master_keys,
		})
	}

	fn build_post_auth_request(&self, url: &str) -> RequestBuilder {
		build_post_auth_request(&self.client, url, &self.api_key)
	}

	fn build_get_auth_request(&self, url: &str) -> RequestBuilder {
		build_get_auth_request(&self.client, url, &self.api_key)
	}

	pub async fn get_base_dir(&self) -> Result<RootDirectory> {
		Ok(self
			.build_get_auth_request("https://gateway.filen.io/v3/user/baseFolder")
			.send()
			.await?
			.json::<FilenResponse<BaseFolderData>>()
			.await?
			.into_data()?
			.uuid
			.into())
	}

	pub async fn list_dir_contents(
		&self,
		dir: &impl Directory,
	) -> Result<(Vec<FileInfo>, Vec<ChildDirectory>)> {
		let response = self
			.build_post_auth_request("https://gateway.filen.io/v3/dir/content")
			.json(&DirContentRequest::from(dir))
			.send()
			.await?;
		// println!("{:?}", response.text().await?);
		let response_data = response
			.json::<FilenResponse<DirContentData>>()
			.await?
			.into_data()?;
		Ok((
			response_data
				.files
				.into_iter()
				.map(|file| FileInfo::from_encrypted(file, &self.master_keys))
				.collect::<Result<Vec<_>>>()?,
			response_data
				.dirs
				.into_iter()
				.map(|dir| ChildDirectory::from_encrypted(dir, &self.master_keys))
				.collect::<Result<Vec<_>>>()?,
		))
	}

	pub async fn download_chunk(&self, file_info: &FileInfo, chunk_idx: u64) -> Result<Vec<u8>> {
		let url = format!(
			"https://{}/{}/{}/{}/{}",
			FILEN_HOSTS[fastrand::usize(..FILEN_HOSTS.len())],
			file_info.get_region(),
			file_info.get_bucket(),
			file_info.get_uuid(),
			chunk_idx
		);
		let response = self.build_get_auth_request(&url).send().await?;
		if !response.status().is_success() {
			return Err(anyhow::anyhow!(
				"Failed to download chunk {:?}",
				response.text().await?
			));
		}
		let mut data: Vec<u8> = response.bytes().await?.into();
		file_info.get_key().decrypt_data(&mut data)?;
		Ok(data)
	}

	pub async fn download_file<W: Write + Seek>(
		&self,
		file_info: &FileInfo,
		writer: &mut W,
	) -> Result<()> {
		let mut futures = FuturesUnordered::new();
		for i in 0..file_info.get_chunks() {
			futures.push(async move { (i, self.download_chunk(file_info, i).await) });
		}
		while let Some((i, chunk)) = futures.next().await {
			writer.seek(std::io::SeekFrom::Start(i * CHUNK_SIZE))?;
			writer.write_all(&chunk?)?;
		}
		Ok(())
	}
}

impl Unautharized for AuthorizedClient {
	fn get_client(&self) -> &reqwest::Client {
		&self.client
	}
}
