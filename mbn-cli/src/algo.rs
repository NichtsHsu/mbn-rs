use asn1_rs::{oid, Oid};

const SHA1: Oid = oid!(1.3.14 .3 .2 .26);

const SHA256: Oid = oid!(2.16.840 .1 .101 .3 .4 .2 .1);

const SHA384: Oid = oid!(2.16.840 .1 .101 .3 .4 .2 .2);

const SHA512: Oid = oid!(2.16.840 .1 .101 .3 .4 .2 .3);

const MD5: Oid = oid!(1.2.840 .113549 .2 .5);

const RSA_ENCRYPTION: Oid = oid!(1.2.840 .113549 .1 .1 .1);

const RSAES_OAEP: Oid = oid!(1.2.840 .113549 .1 .1 .7);

const RSASSA_PSS: Oid = oid!(1.2.840 .113549 .1 .1 .10);

const MD5_RSA_ENCRYPTION: Oid = oid!(1.2.840 .113549 .1 .1 .4);

const MGF1: Oid = oid!(1.2.840 .113549 .1 .1 .8);

const SHA256_RSA_ENCRYPTION: Oid = oid!(1.2.840 .113549 .1 .1 .11);

const SHA348_RSA_ENCRYPTION: Oid = oid!(1.2.840 .113549 .1 .1 .12);

const SHA512_RSA_ENCRYPTION: Oid = oid!(1.2.840 .113549 .1 .1 .13);

pub fn get_algorithm_name(oid: &Oid) -> &'static str {
    if oid == &SHA1 {
        "SHA1"
    } else if oid == &SHA256 {
        "SHA256"
    } else if oid == &SHA384 {
        "SHA384"
    } else if oid == &SHA512 {
        "SHA512"
    } else if oid == &MD5 {
        "MD5"
    } else if oid == &RSA_ENCRYPTION {
        "RSA Encryption"
    } else if oid == &RSAES_OAEP {
        "RSAES-OAEP"
    } else if oid == &RSASSA_PSS {
        "RSASSA-PSS"
    } else if oid == &MD5_RSA_ENCRYPTION {
        "MD5 Encryption"
    } else if oid == &MGF1 {
        "MGF1"
    } else if oid == &SHA256_RSA_ENCRYPTION {
        "SHA256 Encryption"
    } else if oid == &SHA348_RSA_ENCRYPTION {
        "SHA348 Encryption"
    } else if oid == &SHA512_RSA_ENCRYPTION {
        "SHA512 Encryption"
    } else {
        "/* Unknown */"
    }
}
