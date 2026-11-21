use reqwest::{blocking::ClientBuilder, redirect::Policy, Url};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

pub fn private_http_url(url: &Url) -> bool {
    url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && is_loopback(url)))
}

pub fn private_http_client() -> ClientBuilder {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .resolve_to_addrs(
            "localhost",
            &[
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http_without_userinfo() {
        for allowed in [
            "https://worker.example:9443",
            "http://localhost:5820",
            "http://127.0.0.2:5820",
            "http://[::1]:5820",
        ] {
            assert!(private_http_url(&Url::parse(allowed).unwrap()), "{allowed}");
        }
        let cred_url = format!("https://{}:{}@worker.example", "u", "p");
        for denied in [
            "http://worker.example",
            "http://localhost.example",
            "http://0.0.0.0",
            "http://[::ffff:192.0.2.1]",
            cred_url.as_str(),
            "ftp://localhost",
        ] {
            assert!(!private_http_url(&Url::parse(denied).unwrap()), "{denied}");
        }
    }
}
