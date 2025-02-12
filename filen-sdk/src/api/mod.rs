use core::str;

use anyhow::Result;
use reqwest::RequestBuilder;

use crate::crypto::{self, MasterKey, MasterKeys};

pub mod types;
use types::*;

pub fn build_auth_request(
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
	private_key: String,
	public_key: String,
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
		let request = build_auth_request(
			&client,
			"https://gateway.filen.io/v3/user/masterKeys",
			&api_key,
		)
		.json(&MasterKeysRequest {
			master_key: master_key.as_str(),
		})
		.send()
		.await?;
		if !request.status().is_success() {
			return Err(anyhow::anyhow!("Failed to get master keys {:?}", request));
		}

		let master_keys_response: FilenResponse<MasterKeysData> = request.json().await?;
		Ok(Self {
			client,
			api_key,
			private_key,
			public_key,
			master_keys: MasterKeys::new(master_key, &master_keys_response.into_data()?.keys)?,
		})
	}

	fn build_auth_request(&self, url: &str) -> RequestBuilder {
		build_auth_request(&self.client, url, &self.api_key)
	}
}

impl Unautharized for AuthorizedClient {
	fn get_client(&self) -> &reqwest::Client {
		&self.client
	}
}
