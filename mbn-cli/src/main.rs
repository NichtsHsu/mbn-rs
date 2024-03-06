use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

use clap::{self, Args, Parser};
use mbn::{from_elf, HashTableSegment, MbnHeader, Metadata};
use x509_parser::{prelude::*, public_key::PublicKey, signature_algorithm::SignatureAlgorithm};

use crate::algo::get_algorithm_name;

mod algo;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ELF format Qualcomm signed image path.
    elf: String,

    /// Select all contents of hash table segment.
    /// Equivalent to --header --qti-metadata --metadata --hash-table \
    /// --qti-signature --qti-certificate-chain --signature --certificate-chain.
    /// Enabled by default if none of these are specified.
    #[arg(short, long, verbatim_doc_comment)]
    all: bool,

    #[clap(flatten)]
    contents: Contents,

    #[clap(flatten)]
    ops: Operation,
}

#[derive(Args, Debug)]
#[group(id = "contents", multiple = true, conflicts_with = "all")]
struct Contents {
    /// Select MBN header.
    #[arg(long)]
    header: bool,

    /// Select QTI metadata.
    #[arg(long)]
    qti_metadata: bool,

    /// Select OEM metadata.
    #[arg(long)]
    metadata: bool,

    /// Select hash table.
    #[arg(long)]
    hash_table: bool,

    /// Select QTI signature.
    #[arg(long)]
    qti_signature: bool,

    /// Select QTI certificate chain.
    #[arg(long)]
    qti_certificate_chain: bool,

    /// Select OEM signature.
    #[arg(long)]
    signature: bool,

    /// Select OEM certificate chain.
    #[arg(long)]
    certificate_chain: bool,
}

#[derive(Args, Debug)]
#[group(id = "operation", multiple = true)]
struct Operation {
    /// Print information of selected contents.
    /// Enabled by default if none of `-i` and `-d` are specified.
    #[arg(short, long, verbatim_doc_comment)]
    inspect: bool,

    /// Dump selected contents to file.
    #[arg(short, long, value_name = "FILE")]
    dump: Option<String>,
}

const ELF_CODEWORD: u32 = 0x464C457F;

fn run(args: Cli) -> Result<(), mbn::error::ParseError> {
    struct MetadataWrapper {
        metadata: Metadata,
        secboot_ver: u32,
    }
    impl std::fmt::Display for MetadataWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.metadata.fmt(f, self.secboot_ver)
        }
    }

    fn format_hex(raw: &[u8]) -> String {
        raw.iter()
            .fold(String::from("0x"), |s, byte| s + &format!("{:02x}", byte))
    }

    fn format_signature_algorithm(signature_algorithm: &AlgorithmIdentifier<'_>) -> Vec<String> {
        let mut formatted = vec![];
        match SignatureAlgorithm::try_from(signature_algorithm) {
            Ok(algo) => {
                formatted.push(format!(
                    "Signature Algorithm: {}",
                    match algo {
                        SignatureAlgorithm::RSA => "RSA",
                        SignatureAlgorithm::RSASSA_PSS(_) => "RSASSA-PSS",
                        SignatureAlgorithm::RSAAES_OAEP(_) => "RSAES-OAEP",
                        SignatureAlgorithm::DSA => "DSA",
                        SignatureAlgorithm::ECDSA => "ECDSA",
                        SignatureAlgorithm::ED25519 => "ED25519",
                    }
                ));
                match algo {
                    SignatureAlgorithm::RSASSA_PSS(param) => param
                        .hash_algorithm()
                        .map(|algo| get_algorithm_name(algo.oid())),
                    SignatureAlgorithm::RSAAES_OAEP(param) => param
                        .hash_algorithm()
                        .map(|algo| get_algorithm_name(algo.oid())),
                    _ => None,
                }
                .map(|name| formatted.push(format!("Hash Algorithm: {}", name)));
            }
            Err(error) => println!("/* Failed to parse: {} */", error),
        }
        formatted
    }

    fn format_public_key(key: &SubjectPublicKeyInfo) -> Vec<String> {
        let mut formatted = vec![format!(
            "Public Key Algorithm: {}",
            get_algorithm_name(key.algorithm.oid())
        )];
        _ = key.parsed().map(|key| {
            formatted.push(format!("Public Key Size: {} bits", key.key_size()));
            if let PublicKey::RSA(rsa) = key {
                _ = rsa.try_exponent().map(|exponent| {
                    formatted.push(format!("Public Key Exponent: {}", exponent));
                });
            }
        });
        formatted
    }

    let mut buffer = [0; 4];
    let mut file = File::open(&args.elf)?;
    file.read(&mut buffer)?;
    let codeword = u32::from_le_bytes(buffer);
    let hash_table_segment = if codeword == ELF_CODEWORD {
        from_elf(&args.elf)?
    } else {
        file.seek(SeekFrom::Start(0))?;
        let mut raw = vec![];
        file.read_to_end(&mut raw)?;
        HashTableSegment::parse(&raw)?
    };

    if args.ops.inspect {
        if args.contents.header {
            match hash_table_segment.mbn_header {
                MbnHeader::V3Len40(_) => {
                    println!("==========================");
                    println!("# MBN Header V3 (40 bytes)");
                    println!("==========================");
                }
                MbnHeader::V3Len80(_) => {
                    println!("==========================");
                    println!("# MBN Header V3 (80 bytes)");
                    println!("==========================");
                }
                MbnHeader::V5(_) => {
                    println!("===============");
                    println!("# MBN Header V5");
                    println!("===============");
                }
                MbnHeader::V6(_) => {
                    println!("===============");
                    println!("# MBN Header V6");
                    println!("===============");
                }
            }
            println!("{}", hash_table_segment.mbn_header);
            println!("");
        }
        if args.contents.qti_metadata {
            if let Some(metadata) = hash_table_segment.qti_metadata {
                println!("==============");
                println!("# QTI Metadata");
                println!("==============");
                let metadata = MetadataWrapper {
                    metadata: metadata,
                    secboot_ver: match hash_table_segment.mbn_header {
                        MbnHeader::V6(_) => 3,
                        _ => 2,
                    },
                };
                println!("{}", metadata);
                println!("");
            }
        }
        if args.contents.metadata {
            if let Some(metadata) = hash_table_segment.metadata {
                println!("==============");
                println!("# OEM Metadata");
                println!("==============");
                let metadata = MetadataWrapper {
                    metadata: metadata,
                    secboot_ver: match hash_table_segment.mbn_header {
                        MbnHeader::V6(_) => 3,
                        _ => 2,
                    },
                };
                println!("{}", metadata);
                println!("");
            }
        }
        if args.contents.hash_table {
            println!("====================");
            println!("# Hash Table Entries");
            println!("====================");
            hash_table_segment
                .hash_table
                .iter()
                .enumerate()
                .for_each(|(idx, entry)| println!("{:<6}: {}", idx, format_hex(entry)));
            println!("");
        }

        if args.contents.qti_signature || args.contents.qti_certificate_chain {
            let mut raw = &hash_table_segment.qti_certificate_chain as &[u8];
            let mut cert_chain = vec![];
            loop {
                match X509Certificate::from_der(raw) {
                    Ok((remains, cert)) => {
                        cert_chain.push(cert);
                        raw = remains;
                    }
                    Err(_) => break,
                }
            }

            if cert_chain.len() > 0 {
                if args.contents.qti_signature {
                    println!("===============");
                    println!("# QTI Signature");
                    println!("===============");
                    println!(
                        "{}",
                        format_signature_algorithm(&cert_chain[0].signature_algorithm).join("\n")
                    );
                    println!(
                        "{}",
                        format_public_key(cert_chain[0].public_key()).join("\n")
                    );
                    println!("");
                }
                if args.contents.qti_certificate_chain {
                    println!("=======================");
                    println!("# QTI Certificate Chain");
                    println!("=======================");
                    println!("Certificates Number: {}", cert_chain.len());
                    println!("Certificates:");
                    cert_chain.iter().enumerate().for_each(|(idx, cert)| {
                        println!("{:>3}.    Subject: {}", idx, cert.subject());
                        println!("        Issuer: {}", cert.issuer());
                        println!(
                            "        {}",
                            format_signature_algorithm(&cert.signature_algorithm)
                                .join("\n        ")
                        );
                        println!(
                            "        {}",
                            format_public_key(cert.public_key()).join("\n        ")
                        );
                    });
                    println!("");
                }
            }
        }

        if args.contents.signature || args.contents.certificate_chain {
            let mut raw = &hash_table_segment.certificate_chain as &[u8];
            let mut cert_chain = vec![];
            loop {
                match X509Certificate::from_der(raw) {
                    Ok((remains, cert)) => {
                        cert_chain.push(cert);
                        raw = remains;
                    }
                    Err(_) => break,
                }
            }

            if cert_chain.len() > 0 {
                if args.contents.signature {
                    println!("===============");
                    println!("# OEM Signature");
                    println!("===============");
                    println!(
                        "{}",
                        format_signature_algorithm(&cert_chain[0].signature_algorithm).join("\n")
                    );
                    println!(
                        "{}",
                        format_public_key(cert_chain[0].public_key()).join("\n")
                    );
                    println!("");
                }
                if args.contents.certificate_chain {
                    println!("=======================");
                    println!("# OEM Certificate Chain");
                    println!("=======================");
                    println!("Certificates Number: {}", cert_chain.len());
                    println!("Certificates:");
                    cert_chain.iter().enumerate().for_each(|(idx, cert)| {
                        println!("{:>3}.    Subject: {}", idx, cert.subject());
                        println!("        Issuer: {}", cert.issuer());
                        println!(
                            "        {}",
                            format_signature_algorithm(&cert.signature_algorithm)
                                .join("\n        ")
                        );
                        println!(
                            "        {}",
                            format_public_key(cert.public_key()).join("\n        ")
                        );
                    });
                    println!("");
                }
            }
        }
    }

    if let Some(dump_file) = args.ops.dump {
        let mut file = File::create(dump_file)?;
        if args.all {
            hash_table_segment.dump(&mut file, true)?;
        } else {
            if args.contents.header {
                file.write_all(hash_table_segment.mbn_header.as_bytes())?;
            }
            if args.contents.qti_metadata {
                if let Some(metadata) = &hash_table_segment.qti_metadata {
                    file.write_all(metadata.as_bytes())?;
                }
            }
            if args.contents.metadata {
                if let Some(metadata) = &hash_table_segment.metadata {
                    file.write_all(metadata.as_bytes())?;
                }
            }
            if args.contents.hash_table {
                for hash in &hash_table_segment.hash_table {
                    file.write_all(hash)?;
                }
            }
            if args.contents.qti_signature {
                file.write_all(&hash_table_segment.qti_signature)?;
            }
            if args.contents.qti_certificate_chain {
                file.write_all(&hash_table_segment.qti_certificate_chain)?;
            }
            if args.contents.signature {
                file.write_all(&hash_table_segment.signature)?;
            }
            if args.contents.certificate_chain {
                file.write_all(&hash_table_segment.certificate_chain)?;
            }
        }
    }

    Ok(())
}

fn main() {
    let mut args = Cli::parse();

    if !args.contents.header
        && !args.contents.qti_metadata
        && !args.contents.metadata
        && !args.contents.hash_table
        && !args.contents.qti_signature
        && !args.contents.qti_certificate_chain
        && !args.contents.signature
        && !args.contents.certificate_chain
    {
        args.contents.header = true;
        args.contents.qti_metadata = true;
        args.contents.metadata = true;
        args.contents.hash_table = true;
        args.contents.qti_signature = true;
        args.contents.qti_certificate_chain = true;
        args.contents.signature = true;
        args.contents.certificate_chain = true;
    }
    if args.contents.header
        && args.contents.qti_metadata
        && args.contents.metadata
        && args.contents.hash_table
        && args.contents.qti_signature
        && args.contents.qti_certificate_chain
        && args.contents.signature
        && args.contents.certificate_chain
    {
        args.all = true;
    }
    if args.ops.dump.is_none() {
        args.ops.inspect = true;
    }

    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
