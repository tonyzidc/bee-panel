use axum::http::StatusCode;

pub type ApiError = (StatusCode, String);

pub fn domains(values: &[String]) -> Result<(), ApiError> {
    if values.is_empty() || values.len() > 32 || values.iter().any(|value| !domain(value)) {
        return Err((StatusCode::BAD_REQUEST, "Provide valid domain names".into()));
    }
    Ok(())
}

pub fn domain(value: &str) -> bool {
    let value = value.strip_prefix("*.").unwrap_or(value);
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn upstream_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

pub fn destination(value: &str) -> bool {
    upstream_host(value) && !value.contains(['[', ']'])
}

pub fn port(value: u16) -> Result<(), ApiError> {
    if value == 0 {
        Err((
            StatusCode::BAD_REQUEST,
            "Port must be between 1 and 65535".into(),
        ))
    } else {
        Ok(())
    }
}

pub fn scheme(value: &str) -> Result<(), ApiError> {
    if matches!(value, "http" | "https") {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "Scheme must be http or https".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_config_injection() {
        assert!(!domain("example.com;return 200"));
        assert!(!upstream_host("127.0.0.1;"));
        assert!(!destination("other.example.com/path"));
        assert!(domain("*.example.com"));
        assert!(upstream_host("127.0.0.1"));
    }
}
