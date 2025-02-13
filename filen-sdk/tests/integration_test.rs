use core::str;

use filen_sdk::{api::Unautharized, *};

#[tokio::test]
async fn test_login() {
	// If this fails, assume we set the values somewhere else
	dotenvy::dotenv().unwrap_or_default();
	// dotenvy::dotenv().unwrap_or_default();

	let client = api::UnautharizedClient::default();
	let auth_client = client
		.login(
			&std::env::var("TEST_USER_PASSWORD").unwrap(),
			&std::env::var("TEST_USER_EMAIL").unwrap(),
			"XXXXXX",
		)
		.await
		.unwrap();

	let base_dir = auth_client.get_base_dir().await.unwrap();
	let contents = auth_client.list_dir_contents(&base_dir).await.unwrap();
	// single chunk file
	let mut abc_file = std::io::Cursor::new(Vec::new());
	auth_client
		.download_file(&contents.0[0], &mut abc_file)
		.await
		.unwrap();
	assert_eq!(str::from_utf8(abc_file.get_ref()).unwrap(), "abc");
}
