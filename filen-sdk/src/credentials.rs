use anyhow::Result;
use keyring::Entry;

const SERVICE: &str = env!("CARGO_PKG_NAME");

pub fn store_password(username: &str, password: &str) -> Result<()> {
	let entry = Entry::new(SERVICE, username)?;
	entry.set_password(password)?;
	Ok(())
}

pub fn get_password(username: &str) -> Result<Option<String>> {
	let result = Entry::new(SERVICE, username)?.get_password();
	match result {
		Ok(password) => Ok(Some(password)),
		Err(keyring::Error::NoEntry) => Ok(None),
		Err(e) => Err(e.into()),
	}
}

pub fn delete_password(username: &str) -> Result<()> {
	Entry::new(SERVICE, username)?.delete_credential()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	const TEST_USERNAME: &str = "test";
	const TEST_PASSWORD: &str = "specialpassword";

	#[test]
	fn store_retrieve() {
		store_password(TEST_USERNAME, TEST_PASSWORD).unwrap();
		assert_eq!(get_password(TEST_USERNAME).unwrap().unwrap(), TEST_PASSWORD);
	}

	#[test]
	fn delete() {
		store_password(TEST_USERNAME, TEST_PASSWORD).unwrap();
		delete_password(TEST_USERNAME).unwrap();
		assert_eq!(get_password(TEST_USERNAME).unwrap(), None);
	}
}
