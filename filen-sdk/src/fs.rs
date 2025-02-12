use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto::MasterKeys;

pub trait Directory {
	fn get_uuid(&self) -> Uuid;
}

pub struct RootDirectory {
	uuid: Uuid,
}

impl From<Uuid> for RootDirectory {
	fn from(uuid: Uuid) -> Self {
		Self { uuid }
	}
}

impl Directory for RootDirectory {
	fn get_uuid(&self) -> Uuid {
		self.uuid
	}
}

#[derive(Deserialize, Debug)]
pub struct EncryptedChildDirectory {
	uuid: Uuid,
	name: String,
	parent: Uuid,
	color: Option<String>,
	#[serde(deserialize_with = "chrono::serde::ts_seconds::deserialize")]
	timestamp: DateTime<Utc>,
	favorited: u8,
	is_sync: u8,
	is_default: u8,
}

impl Directory for EncryptedChildDirectory {
	fn get_uuid(&self) -> Uuid {
		self.uuid
	}
}

#[derive(Debug)]
pub struct ChildDirectory {
	uuid: Uuid,
	name: String,
	parent: Uuid,
	color: Option<String>,
	timestamp: DateTime<Utc>,
	favorited: u8,
	is_sync: u8,
	is_default: u8,
}

impl Directory for ChildDirectory {
	fn get_uuid(&self) -> Uuid {
		self.uuid
	}
}

#[derive(Deserialize)]
struct ChildDirectoryName {
	name: String,
}

impl ChildDirectory {
	pub fn from_encrypted(
		encrypted: EncryptedChildDirectory,
		master_keys: &MasterKeys,
	) -> Result<Self> {
		// might be possible to optimize this to decrypt in place?
		let mut name = String::new();
		master_keys.decrypt_metadata(&encrypted.name, &mut name)?;
		let name: ChildDirectoryName = serde_json::from_str(&name)?;
		Ok(Self {
			uuid: encrypted.uuid,
			name: name.name,
			parent: encrypted.parent,
			color: encrypted.color,
			timestamp: encrypted.timestamp,
			favorited: encrypted.favorited,
			is_sync: encrypted.is_sync,
			is_default: encrypted.is_default,
		})
	}
}

#[derive(Deserialize, Debug)]
pub struct EncryptedFile {
	uuid: Uuid,
	metadata: String,
	rm: String,
	#[serde(deserialize_with = "chrono::serde::ts_seconds::deserialize")]
	timestamp: DateTime<Utc>,
	chunks: u64,
	size: u64,
	bucket: String,
	region: String,
	parent: Uuid,
	version: u64,
	favorited: u8,
}

#[derive(Debug)]
pub struct File {
	uuid: Uuid,
	metadata: Metadata,
	rm: String,
	timestamp: DateTime<Utc>,
	chunks: u64,
	size: u64,
	bucket: String,
	region: String,
	parent: Uuid,
	version: u64,
	favorited: u8,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
	name: String,
	size: u64,
	mime: String,
	key: String,
	#[serde(rename = "lastModified")]
	#[serde(deserialize_with = "chrono::serde::ts_milliseconds::deserialize")]
	last_modified: DateTime<Utc>,
}

impl File {
	pub fn from_encrypted(encrypted: EncryptedFile, master_keys: &MasterKeys) -> Result<Self> {
		// might be possible to optimize this to decrypt in place?
		let mut metadata = String::new();
		master_keys.decrypt_metadata(&encrypted.metadata, &mut metadata)?;
		Ok(Self {
			uuid: encrypted.uuid,
			metadata: serde_json::from_str(&metadata)?,
			rm: encrypted.rm,
			timestamp: encrypted.timestamp,
			chunks: encrypted.chunks,
			size: encrypted.size,
			bucket: encrypted.bucket,
			region: encrypted.region,
			parent: encrypted.parent,
			version: encrypted.version,
			favorited: encrypted.favorited,
		})
	}
}
