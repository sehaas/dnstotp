use chrono::{Timelike, Utc};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use tokio::net::UdpSocket;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{error, info};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::rr::{Label, LowerName, Name},
    proto::{
        op::{Header, ResponseCode},
        rr::{rdata::TXT, RData, Record},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

struct Handler {
    otp_zone: LowerName,
    tokens: Arc<RwLock<HashMap<String, TOTP>>>,
}

impl Handler {
    pub fn new() -> Self {
        Handler {
            otp_zone: LowerName::from(Name::from_ascii("otp.deebas.com").unwrap()),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn handle_request_error<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let response = MessageResponseBuilder::from_message_request(request);

        response_handle
            .send_response(response.error_msg(request.header(), ResponseCode::ServFail))
            .await
            .unwrap()
    }
    async fn send_txt<R: ResponseHandler>(
        &self,
        txt: String,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![txt]));
        let now = Utc::now();
        let ttl = 30 - now.second() % 30;
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        response_handle.send_response(response).await.unwrap()
    }

    fn split_name(&self, name: &Name, nr_labels: usize) -> HashMap<usize, Label> {
        name.iter()
            .enumerate()
            .filter(|(i, n)| {
                info!("label: {:?}", n);
                i < &nr_labels
            })
            .fold(HashMap::new(), |mut m, (i, n)| {
                m.insert(i, Label::from_raw_bytes(n).unwrap());
                return m;
            })
    }

    fn do_handle_request(&self, request: &Request) -> Result<String, String> {
        let query = request.query();
        let name = query.original().name();
        if name.is_wildcard() {
            return Err(String::from("wildcard"));
        }

        if !self.otp_zone.zone_of(&LowerName::from(name)) {
            return Err(String::from("wrong zone"));
        }

        let nr_labels = (name.num_labels() - self.otp_zone.num_labels()) as usize;

        info!("nr: {}", nr_labels);
        match nr_labels {
            nr if nr == 1 => {
                let name_parts = self.split_name(name, nr);
                let key = name_parts.get(&0).unwrap().to_ascii();

                let map = self.tokens.read().expect("ro lock failed");
                let totp = map.get(&key);

                match totp {
                    Some(t) => {
                        let token = t.generate_current().unwrap();
                        info!("Account: {} => Token: {}", key, token);
                        return Ok(token);
                    }
                    None => {
                        error!("unknown account: {}", key);
                        return Err(String::from("unknown account"));
                    }
                }
            }
            nr if nr == 2 => {
                let name_parts = self.split_name(name, nr);
                let secret = name_parts.get(&0).unwrap().to_ascii();
                let key = name_parts.get(&1).unwrap().to_ascii();
                info!("add account: {} => {}", key, secret);
                let totp = TOTP::new_unchecked(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    Secret::Encoded(secret).to_bytes().unwrap(),
                );
                {
                    let mut map = self.tokens.write().expect("rw lock failed");
                    map.insert(key, totp);
                }
                return Ok(String::from("added"));
            }
            _ => return Err(String::from("error")),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        match self.do_handle_request(request) {
            Ok(info) => self.send_txt(info, request, response_handle).await,
            Err(msg) => {
                error!("returned: {}", msg);
                self.handle_request_error(request, response_handle).await
            }
        }
    }
}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::init();

    let catalog = Handler::new();
    let mut server = ServerFuture::new(catalog);
    server.register_socket(UdpSocket::bind("0.0.0.0:1053").await.unwrap());
    server.block_until_done().await.unwrap();
}
