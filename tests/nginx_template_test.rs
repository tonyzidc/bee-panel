use minijinja::{context, Environment};

#[test]
fn test_proxy_host_template_rendering() {
    let mut env = Environment::new();
    let template_str = include_str!("../templates/nginx/proxy_host.j2");
    env.add_template("proxy_host", template_str).unwrap();

    let tmpl = env.get_template("proxy_host").unwrap();
    let rendered = tmpl
        .render(context! {
            domain_names => vec!["example.com", "www.example.com"],
            forward_scheme => "http",
            forward_host => "127.0.0.1",
            forward_port => 8080,
            caching_enabled => true,
            block_exploits => true,
            websocket_support => true,
            ssl_certificate_id => None::<i64>,
            ssl_forced => false,
            http2_support => true,
            hsts_enabled => false,
            hsts_subdomains => false,
            access_list_id => None::<i64>,
            custom_locations => Vec::<String>::new(),
            advanced_config => "",
        })
        .unwrap();

    assert!(rendered.contains("server_name example.com www.example.com;"));
    assert!(rendered.contains("proxy_pass http://127.0.0.1:8080;"));
    assert!(rendered.contains("proxy_set_header Upgrade $http_upgrade;"));
    assert!(rendered.contains("proxy_cache_valid 200 302 10m;"));
}

#[test]
fn test_stream_template_rendering() {
    let mut env = Environment::new();
    let template_str = include_str!("../templates/nginx/stream.j2");
    env.add_template("stream", template_str).unwrap();

    let tmpl = env.get_template("stream").unwrap();
    let rendered = tmpl
        .render(context! {
            incoming_port => 3306,
            forward_host => "10.0.0.5",
            forward_port => 3306,
            tcp_forwarding => true,
            udp_forwarding => false,
        })
        .unwrap();

    assert!(rendered.contains("listen 3306;"));
    assert!(rendered.contains("proxy_pass 10.0.0.5:3306;"));
}

#[test]
fn test_redirection_host_template_rendering() {
    let mut env = Environment::new();
    let template_str = include_str!("../templates/nginx/redirection_host.j2");
    env.add_template("redirection_host", template_str).unwrap();

    let tmpl = env.get_template("redirection_host").unwrap();
    let rendered = tmpl
        .render(context! {
            domain_names => vec!["old-site.com"],
            forward_http_code => 301,
            forward_scheme => "https",
            forward_domain => "new-site.com",
            preserve_path => true,
            block_exploits => true,
            ssl_certificate_id => None::<i64>,
        })
        .unwrap();

    assert!(rendered.contains("server_name old-site.com;"));
    assert!(rendered.contains("return 301 https://new-site.com$request_uri;"));
}
