#[macro_use]
extern crate anyhow;

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::Context;
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tokio_postgres::{Client, SimpleQueryMessage, SimpleQueryRow};

#[derive(StructOpt)]
struct Opt {
    /// Domain to search for.
    ///
    /// This domain and all subdomains will be searched.
    #[structopt(short = "d", long = "domain", required = true)]
    domains: Vec<String>,

    /// Log certs in json
    #[structopt(long = "json-log")]
    json_log: bool,

    /// Path to directory in which crtshmon can maintain state.
    ///
    /// crtshmon will write a file to this directory, which is used for keeping track of which
    /// certificates have already been seen and alerted on.
    #[structopt(long = "directory", default_value = ".")]
    state_dir: PathBuf,
}

/// Represents the stored state of the program.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// The certificates that we've already seen.
    seen_certificates: SeenCertificates,
}
impl State {
    fn read(path: &Path) -> Result<Self, anyhow::Error> {
        let f = match File::open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(anyhow::Error::from(e)
                    .context(format!("Error opening state file at {}", path.display())))
            }
            Ok(x) => x,
        };

        let mut f = BufReader::new(f);
        let state: State = serde_json::from_reader(&mut f)
            .with_context(|| format!("Error deserializing state file at {}", path.display()))?;

        Ok(state)
    }

    fn write(&self, path: &Path, tmp_path: &Path) -> Result<(), anyhow::Error> {
        // Write to tmp_path, fsync, then rename into path
        let f = File::create(tmp_path).with_context(|| {
            format!(
                "Error creating temporary state file at {}",
                tmp_path.display()
            )
        })?;
        let mut f = BufWriter::new(f);
        serde_json::to_writer(&mut f, self).with_context(|| {
            format!(
                "Error writing to temporary state file at {}",
                tmp_path.display()
            )
        })?;
        let f = f.into_inner().with_context(|| {
            format!(
                "Error writing to temporary state file at {}",
                tmp_path.display()
            )
        })?;
        f.sync_all()?;
        std::fs::rename(tmp_path, path).with_context(|| {
            format!(
                "Error renaming file {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;

        Ok(())
    }
}
#[derive(Default, Serialize, Deserialize)]
struct SeenCertificates {
    sha256_fingerprints: BTreeSet<String>,
}

/// Represents a single returned row from the database.
#[derive(Serialize)]
struct TypedRow {
    // https://github.com/serde-rs/serde/issues/760
    message: &'static str,
    issuer_name: String,
    common_name: String,
    san: String,
    certificate_id: i64,
    not_after: String,
    not_before: String,
    sha256_fingerprint: String,
}
impl TryFrom<&SimpleQueryRow> for TypedRow {
    type Error = anyhow::Error;
    fn try_from(row: &SimpleQueryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            message: "Found new certificate",
            issuer_name: row
                .try_get("issuer_name")?
                .ok_or_else(|| format_err!("issuer_name was None"))?
                .into(),
            common_name: row
                .try_get("common_name")?
                .ok_or_else(|| format_err!("common_name was None"))?
                .into(),
            san: row
                .try_get("sans")?
                .ok_or_else(|| format_err!("sans was None"))?
                .into(),
            certificate_id: row
                .try_get("certificate_id")?
                .ok_or_else(|| format_err!("certificate_id was None"))?
                .parse()?,
            not_before: row
                .try_get("not_before")?
                .ok_or_else(|| format_err!("not_before was None"))?
                .into(),
            not_after: row
                .try_get("not_after")?
                .ok_or_else(|| format_err!("not_after was None"))?
                .into(),
            sha256_fingerprint: row
                .try_get("sha256_fingerprint")?
                .ok_or_else(|| format_err!("sha256_fingerprint was None"))?
                .into(),
        })
    }
}
impl TypedRow {
    fn log(&self, opt: &Opt) -> Result<(), anyhow::Error> {
        if opt.json_log {
            let value = serde_json::to_string(self)?;
            println!("{}", value);
        } else {
            #[rustfmt::skip]
            println!(
"Found new certificate:
Link: {link}
Issuer: {issuer}
CN: {cn}
SAN: {san}
NotAfter: {notafter}
NotBefore: {notbefore}
Fingerprint: {fingerprint}
",
                link = format_args!("https://crt.sh/?id={}", self.certificate_id),
                issuer = self.issuer_name,
                cn = self.common_name,
                san = self.san,
                notafter = self.not_after,
                notbefore = self.not_before,
                fingerprint = self.sha256_fingerprint,
            );
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let state_file = opt.state_dir.join("crtshmon.json");
    let tmp_file = opt.state_dir.join("crtshmon.tmp");

    let mut state = State::read(&state_file)?;

    let builder = SslConnector::builder(SslMethod::tls())?;
    let connector = MakeTlsConnector::new(builder.build());

    let (client, connection) = tokio_postgres::connect(
        "host=crt.sh dbname=certwatch user=guest sslmode=require",
        connector,
    )
    .await
    .context("Error connecting to crt.sh")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("Connection error: {}", e);
        }
    });

    // Run in parallel?
    for domain in &opt.domains {
        let rows = query_domain(&client, domain)
            .await
            .with_context(|| format!("Error querying domain {}", domain))?;

        for row in &rows {
            if state
                .seen_certificates
                .sha256_fingerprints
                .insert(row.sha256_fingerprint.to_owned())
            {
                row.log(&opt).context("Error logging certificate")?;
            }
        }
    }

    state.write(&state_file, &tmp_file).with_context(|| {
        format!(
            "Error writing state file to directory {}",
            opt.state_dir.display()
        )
    })?;

    Ok(())
}

async fn query_domain(client: &Client, domain: &str) -> Result<Vec<TypedRow>, anyhow::Error> {
    // Use simple_query because crt.sh doesn't support prepared statements.
    // Trivial SQL injection if you supply invalid domain arguments, but no valid domain can
    // contain '
    let q = format!(include_str!("query.sql"), domain = domain);
    let rows = client.simple_query(&q).await?;
    rows.iter()
        .filter_map(|row| match row {
            SimpleQueryMessage::Row(r) => Some(r),
            _ => None,
        })
        .map(TypedRow::try_from)
        .collect()
}
