use flagkit::FlagKitOptions;

// Test the get_base_url function which is exposed from http module
mod http_base_url_tests {
    use super::*;

    #[test]
    fn test_base_url_default() {
        let options = FlagKitOptions::builder("sdk_test_key").build();

        // Without local_port, should use production URL
        assert!(options.local_port.is_none());
    }

    #[test]
    fn test_base_url_with_local_port() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(8200)
            .build();

        assert_eq!(options.local_port, Some(8200));
    }

    #[test]
    fn test_base_url_with_custom_port() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(3000)
            .build();

        assert_eq!(options.local_port, Some(3000));
    }

    #[test]
    fn test_base_url_with_port_80() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(80)
            .build();

        assert_eq!(options.local_port, Some(80));
    }

    #[test]
    fn test_base_url_with_port_443() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .local_port(443)
            .build();

        assert_eq!(options.local_port, Some(443));
    }
}

// Test HTTP client configuration
mod http_client_config_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_timeout_configuration() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .timeout(Duration::from_secs(30))
            .build();

        assert_eq!(options.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_retry_attempts_configuration() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .retry_attempts(5)
            .build();

        assert_eq!(options.retry_attempts, 5);
    }

    #[test]
    fn test_circuit_breaker_threshold_configuration() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .circuit_breaker_threshold(10)
            .build();

        assert_eq!(options.circuit_breaker_threshold, 10);
    }

    #[test]
    fn test_circuit_breaker_reset_timeout_configuration() {
        let options = FlagKitOptions::builder("sdk_test_key")
            .circuit_breaker_reset_timeout(Duration::from_secs(60))
            .build();

        assert_eq!(options.circuit_breaker_reset_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_default_timeout() {
        let options = FlagKitOptions::new("sdk_test_key");

        assert_eq!(options.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_default_retry_attempts() {
        let options = FlagKitOptions::new("sdk_test_key");

        assert_eq!(options.retry_attempts, 3);
    }

    #[test]
    fn test_default_circuit_breaker_threshold() {
        let options = FlagKitOptions::new("sdk_test_key");

        assert_eq!(options.circuit_breaker_threshold, 5);
    }

    #[test]
    fn test_default_circuit_breaker_reset_timeout() {
        let options = FlagKitOptions::new("sdk_test_key");

        assert_eq!(options.circuit_breaker_reset_timeout, Duration::from_secs(30));
    }
}
