use axum::{
    body::Body,
    http::{header::{HeaderName, HeaderValue, SET_COOKIE}, Request, Response},
    middleware::Next,
};

pub async fn security_headers(
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut response = next.run(req).await;
    
    // Add HSTS
    response.headers_mut().insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );
    
    // Mandate SameSite=Strict
    let mut new_cookies = Vec::new();
    for cookie in response.headers().get_all(SET_COOKIE).iter() {
        if let Ok(cookie_str) = cookie.to_str() {
            if !cookie_str.contains("SameSite") {
                let new_cookie = format!("{}; SameSite=Strict", cookie_str);
                if let Ok(new_val) = HeaderValue::from_str(&new_cookie) {
                    new_cookies.push(new_val);
                    continue;
                }
            }
        }
        new_cookies.push(cookie.clone());
    }
    response.headers_mut().remove(SET_COOKIE);
    for cookie in new_cookies {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    
    response
}
