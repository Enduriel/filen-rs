use filen_sdk::{api::Unautharized, *};

#[tokio::test]
async fn test_login() {
	// If this fails, assume we set the values somewhere else
	dotenvy::dotenv().unwrap_or_default();
	// dotenvy::dotenv().unwrap_or_default();

	let client = api::UnautharizedClient::default();
	let _ = client
		.login(
			&std::env::var("TEST_USER_PASSWORD").unwrap(),
			&std::env::var("TEST_USER_EMAIL").unwrap(),
			"XXXXXX",
		)
		.await
		.unwrap();
}
