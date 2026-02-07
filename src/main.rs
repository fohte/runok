fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[rstest]
    fn clap_derive_is_available() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[arg(long)]
            name: Option<String>,
        }

        let cli = TestCli::parse_from(["test", "--name", "hello"]);
        assert_eq!(cli.name.as_deref(), Some("hello"));
    }

    #[rstest]
    fn serde_derive_is_available() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestConfig {
            key: String,
        }

        let config = TestConfig {
            key: "value".to_string(),
        };
        assert_eq!(config.key, "value");
    }

    #[rstest]
    fn anyhow_is_available() {
        use anyhow::{Context, Result};

        fn fallible() -> Result<i32> {
            let val: i32 = "42".parse().context("parse failed")?;
            Ok(val)
        }

        assert_eq!(fallible().unwrap(), 42);
    }

    #[rstest]
    fn thiserror_is_available() {
        use thiserror::Error;

        #[derive(Error, Debug)]
        enum TestError {
            #[error("test error: {0}")]
            Test(String),
        }

        let err = TestError::Test("hello".to_string());
        assert_eq!(err.to_string(), "test error: hello");
    }
}
