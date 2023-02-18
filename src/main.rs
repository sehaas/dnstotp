use chrono::{Timelike, Utc};
use microkv::{namespace::ExtendedIndexMap, MicroKV};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use clap::Parser;
use sha2::{Digest, Sha512};

use tokio::net::UdpSocket;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{debug, error, info, trace};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::rr::{Label, LowerName, Name},
    proto::{
        op::{Header, ResponseCode},
        rr::{
            rdata::{SOA, TXT},
            RData, Record, RecordType,
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "DIR", default_value = "./")]
    database: String,

    #[arg(short = 'z', long, value_name = "ZONE")]
    dns_zone: Name,

    #[arg(short, long, value_name = "NAMESERVER")]
    nameserver: Name,

    #[arg(short, long, value_name = "SOCKET", default_value = "0.0.0.0:1053")]
    bind: SocketAddr,
}

struct Handler {
    query_zone: LowerName,
    new_zone: LowerName,
    name_server: Name,
    store: MicroKV,
}

impl Handler {
    pub fn new(cli: &Cli) -> Self {
        Handler {
            query_zone: LowerName::from(cli.dns_zone.clone()),
            new_zone: LowerName::from(
                Name::from_ascii("new")
                    .unwrap()
                    .append_name(&cli.dns_zone)
                    .unwrap(),
            ),
            name_server: cli.nameserver.clone(),
            store: MicroKV::open_with_base_path("dnstotp-db", PathBuf::from(&cli.database))
                .expect("no DB")
                .set_auto_commit(true),
        }
    }

    fn generate_ipv4(&self, token: &str) -> Option<Ipv4Addr> {
        let digits = token.as_bytes();

        let pattern = [
            [2, 1, 1, 2],
            [1, 2, 2, 1],
            [2, 2, 1, 1],
            [1, 1, 2, 2],
            [1, 2, 1, 2],
            [2, 1, 2, 1],
            [3, 1, 1, 1],
            [1, 3, 1, 1],
            [1, 1, 3, 1],
            [1, 1, 1, 3],
        ];

        'pattern_loop: for p in pattern {
            let mut result: [u8; 6] = [0; 6];
            let mut r_idx = 0;
            let mut bpo = 0;
            for idx in 0..6 {
                let c = result[r_idx]
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digits[idx] - 48));
                match c {
                    Some(v) => result[r_idx] = v,
                    None => {
                        error!("ERR: invalid octet: {}, pattern: {:?}", token, p);
                        continue 'pattern_loop;
                    }
                }
                bpo = bpo + 1;
                if bpo >= p[r_idx] {
                    r_idx = r_idx + 1;
                    bpo = 0;
                }
            }
            let ipv4 = Ipv4Addr::new(result[0], result[1], result[2], result[3]);
            let ipv4_str = ipv4.to_string();
            if ipv4_str.len() == 9 {
                return Some(ipv4);
            }
        }

        None
    }

    fn generate_txt(&self, txt: &String, ttl: u32, query: &Name) -> Record {
        let rdata = RData::TXT(TXT::new(vec![txt.clone()]));
        Record::from_rdata(query.to_owned(), ttl, rdata)
    }

    async fn handle_request_error<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let response = MessageResponseBuilder::from_message_request(request);

        response_handle
            .send_response(response.error_msg(request.header(), ResponseCode::Refused))
            .await
            .unwrap()
    }
    async fn send_response<R: ResponseHandler>(
        &self,
        records: Vec<Record>,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        response_handle.send_response(response).await.unwrap()
    }

    fn split_name(&self, name: &Name, nr_labels: usize) -> HashMap<usize, Label> {
        name.iter()
            .enumerate()
            .filter(|(i, n)| {
                trace!("label: {:?}", n);
                i < &nr_labels
            })
            .fold(HashMap::new(), |mut m, (i, n)| {
                m.insert(i, Label::from_raw_bytes(n).unwrap());
                return m;
            })
    }

    fn do_handle_request(&self, request: &Request) -> Result<Vec<Record>, String> {
        let query = request.query();
        let name = query.original().name();
        if name.is_wildcard() {
            return Err(String::from("wildcard"));
        }

        match LowerName::from(name) {
            sub if self.new_zone == sub.base_name() => {
                let name_parts =
                    self.split_name(&name.trim_to((self.new_zone.num_labels() + 1) as usize), 1);
                let secret = name_parts.get(&0).unwrap().to_ascii();
                let mut hasher = Sha512::new();
                hasher.update(secret.as_bytes());
                let key = String::from(format!("{:x}", hasher.finalize()).get(0..6).unwrap());

                info!("add account: {} => {}", key, secret);
                _ = self.store.lock_write(|s| {
                    s.kv_put(&self.store, "", key.clone(), &secret);
                });

                let cname = Name::from_str(key.as_str())
                    .unwrap()
                    .append_domain(&Name::from(self.query_zone.clone()))
                    .unwrap();
                let rdata = RData::CNAME(cname.clone());
                let records = vec![
                    Record::from_rdata(query.name().into(), 3600, rdata),
                    self.generate_txt(
                        &format!("you can now query {} for your TOTP", cname),
                        3600,
                        name,
                    ),
                ];

                return Ok(records);
            }
            sub if self.query_zone == sub.base_name() => {
                let name_parts = self.split_name(
                    &name.trim_to((self.query_zone.num_labels() + 1) as usize),
                    1,
                );
                let key = name_parts.get(&0).unwrap().to_ascii();

                let totp = self
                    .store
                    .lock_read(|s| s.kv_get::<String>(&self.store, "", key.clone()).unwrap())
                    .unwrap();

                match totp {
                    Some(s) => {
                        let t = TOTP::new_unchecked(
                            Algorithm::SHA1,
                            6,
                            1,
                            30,
                            Secret::Encoded(s).to_bytes().unwrap(),
                        );
                        let token = t.generate_current().unwrap();
                        info!("Account: {} => Token: {}", key, token);

                        let now = Utc::now();
                        let ttl = 30 - now.second() % 30;

                        let ipv4 = self
                            .generate_ipv4(&token.as_str())
                            .unwrap_or_else(|| Ipv4Addr::new(0, 0, 0, 0));
                        let records = vec![
                            Record::from_rdata(query.name().into(), ttl, RData::A(ipv4)),
                            self.generate_txt(&token, ttl, name),
                        ];
                        return Ok(records);
                    }
                    None => {
                        error!("unknown account: {}", key);
                        return Err(String::from("unknown account"));
                    }
                }
            }
            sub if self.query_zone == sub => {
                match query.query_type() {
                    rt if RecordType::AAAA == rt => {
                        debug!("got AAAA");
                    }
                    rt if RecordType::A == rt => {
                        debug!("got A");
                    }
                    rt if RecordType::SOA == rt => {
                        info!("got SOA");
                        let rdata = RData::SOA(SOA::new(
                            self.name_server.clone(),
                            self.name_server.clone(),
                            2023012704,
                            10800,
                            1800,
                            604800,
                            86400,
                        ));
                        let records = vec![Record::from_rdata(query.name().into(), 3600, rdata)];
                        return Ok(records);
                    }
                    rt if RecordType::TXT == rt => {
                        debug!("got TXT");
                    }
                    rt if RecordType::NS == rt => {
                        info!("got NS");
                        let rdata = RData::NS(self.name_server.clone());
                        return Ok(vec![Record::from_rdata(query.name().into(), 3600, rdata)]);
                    }
                    rt => {
                        debug!("got something else: {}", rt);
                    }
                }
                return Ok(vec![
                    self.generate_txt(&format!("USAGE:"), 3600, &query.name().into()),
                    self.generate_txt(
                        &format!("  register: dig <secret>.{}", self.new_zone),
                        3600,
                        &query.name().into(),
                    ),
                    self.generate_txt(
                        &format!("  query: dig <key>.{}", self.query_zone),
                        3600,
                        &query.name().into(),
                    ),
                ]);
            }
            _ => {
                return Err(String::from("wrong zone"));
            }
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
            Ok(info) => self.send_response(info, request, response_handle).await,
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

    let cli = Cli::parse();
    debug!("CLI: {:?}", cli);

    let catalog = Handler::new(&cli);
    let mut server = ServerFuture::new(catalog);
    server.register_socket(UdpSocket::bind(cli.bind).await.unwrap());
    server.block_until_done().await.unwrap();
}
