// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{build_to_vec, TpmError, TpmErrorKind};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use hmac::{Hmac, Mac};
use num_traits::FromPrimitive;
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, SecretKey,
};
use p384::{
    ecdh::diffie_hellman as p384_ecdh, elliptic_curve::sec1::ToEncodedPoint as ToEncodedPoint384,
    AffinePoint as AffinePoint384, NistP384, PublicKey as PublicKey384, SecretKey as SecretKey384,
};
use p521::{
    ecdh::diffie_hellman as p521_ecdh, elliptic_curve::sec1::ToEncodedPoint as ToEncodedPoint521,
    AffinePoint as AffinePoint521, NistP521, PublicKey as PublicKey521, SecretKey as SecretKey521,
};
use pkcs8::{
    der::{
        self,
        asn1::{AnyRef, OctetString},
        Decode, DecodeValue, Encode, EncodeValue, Reader, Sequence, Writer,
    },
    DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
};
use rand::{thread_rng, RngCore};
use rsa::{traits::PublicKeyParts, Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{
        Tpm2b, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPrivate,
        Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmEccCurve, TpmaObject, TpmsAuthCommand, TpmsEccPoint,
        TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
    },
    TpmBuild, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const ID_IMPORTABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.4");
pub const ID_SEALED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.5");
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TpmKeyAsn1 {
    pub oid: ObjectIdentifier,
    pub parent: u32,
    pub pub_key: OctetString,
    pub priv_key: OctetString,
}

impl Sequence<'_> for TpmKeyAsn1 {}

impl<'a> DecodeValue<'a> for TpmKeyAsn1 {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        reader.sequence(|reader| {
            let oid = ObjectIdentifier::decode(reader)?;
            let parent = u32::decode(reader)?;
            let pub_key = OctetString::decode(reader)?;
            let priv_key = OctetString::decode(reader)?;
            Ok(Self {
                oid,
                parent,
                pub_key,
                priv_key,
            })
        })
    }
}

impl EncodeValue for TpmKeyAsn1 {
    fn value_len(&self) -> der::Result<der::Length> {
        self.oid.encoded_len()?
            + self.parent.encoded_len()?
            + self.pub_key.encoded_len()?
            + self.priv_key.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.oid.encode(writer)?;
        self.parent.encode(writer)?;
        self.pub_key.encode(writer)?;
        self.priv_key.encode(writer)?;
        Ok(())
    }
}

/// Loaded private key from PEM file.
pub struct PrivateKey {
    private_key_info_der: Vec<u8>,
}

impl PrivateKey {
    /// Load and parse PEM-encoded PKCS#8 private key.
    ///
    /// # Errors
    ///
    /// Returns `TpmError`.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self, TpmError> {
        let pem_bytes =
            std::fs::read(path).map_err(|e| TpmError::File(path.display().to_string(), e))?;
        let pem_str = std::str::from_utf8(&pem_bytes)
            .map_err(|e| TpmError::Parse(format!("UTF-8 error: {e}")))?;

        let pem_block =
            pem::parse(pem_str).map_err(|e| TpmError::Parse(format!("PEM parse error: {e}")))?;

        if pem_block.tag() != "PRIVATE KEY" {
            return Err(TpmError::Parse(format!(
                "invalid PEM tag: {}",
                pem_block.tag()
            )));
        }

        let contents = pem_block.contents().to_vec();

        PrivateKeyInfo::from_der(&contents)
            .map_err(|e| TpmError::Parse(format!("DER parse error: {e}")))?;

        Ok(Self {
            private_key_info_der: contents,
        })
    }

    /// Convert to TPM's `TpmtPublic` data.
    ///
    /// # Errors
    ///
    /// Returns `TpmError`.
    pub fn to_tpmt_public(&self, hash_alg: TpmAlgId) -> Result<TpmtPublic, TpmError> {
        let private_key_info = PrivateKeyInfo::from_der(&self.private_key_info_der)
            .map_err(|e| TpmError::Parse(format!("DER parse error: {e}")))?;

        let oid = private_key_info.algorithm.oid;
        let object_type = match oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => TpmAlgId::Rsa,
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => TpmAlgId::Ecc,
            _ => {
                return Err(TpmError::Parse(
                    "unsupported key algorithm in PEM file".to_string(),
                ))
            }
        };

        match object_type {
            TpmAlgId::Rsa => {
                let rsa_key = RsaPrivateKey::from_pkcs8_der(&self.private_key_info_der)
                    .map_err(|e| TpmError::Parse(format!("RSA parse error: {e}")))?;

                let modulus_bytes = rsa_key.n().to_bytes_be();
                let key_bits = u16::try_from(modulus_bytes.len() * 8)
                    .map_err(|_| TpmError::Parse("RSA key size too large".to_string()))?;

                let public_exponent = {
                    let e_bytes = rsa_key.e().to_bytes_be();
                    if e_bytes.len() > 4 {
                        return Err(TpmError::Parse(
                            "RSA public exponent is larger than 32 bits and is not supported for import."
                                .to_string(),
                        ));
                    }
                    let mut buf = [0u8; 4];
                    buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
                    u32::from_be_bytes(buf)
                };

                Ok(TpmtPublic {
                    object_type,
                    name_alg: hash_alg,
                    object_attributes: TpmaObject::RESTRICTED
                        | TpmaObject::DECRYPT
                        | TpmaObject::FIXED_TPM
                        | TpmaObject::FIXED_PARENT,
                    auth_policy: Tpm2bDigest::default(),
                    parameters: TpmuPublicParms::Rsa {
                        symmetric: TpmtSymDefObject::default(),
                        scheme: TpmtScheme::default(),
                        key_bits,
                        exponent: public_exponent,
                    },
                    unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::try_from(
                        modulus_bytes.as_slice(),
                    )?),
                })
            }
            TpmAlgId::Ecc => {
                let secret_key = SecretKey::from_pkcs8_der(&self.private_key_info_der)
                    .map_err(|e| TpmError::Parse(format!("ECC key parse error: {e}")))?;

                let encoded_point = secret_key.public_key().to_encoded_point(false);
                let pub_bytes = encoded_point.as_bytes();

                if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
                    return Err(TpmError::Parse("invalid ECC public key format".to_string()));
                }

                let coord_len = (pub_bytes.len() - 1) / 2;
                let x = &pub_bytes[1..=coord_len];
                let y = &pub_bytes[1 + coord_len..];

                let params = private_key_info
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or_else(|| TpmError::Parse("missing ECC curve parameters".to_string()))?;

                let curve_id = ec_oid_to_tpm_curve(params)?;

                Ok(TpmtPublic {
                    object_type,
                    name_alg: hash_alg,
                    object_attributes: TpmaObject::RESTRICTED
                        | TpmaObject::DECRYPT
                        | TpmaObject::FIXED_TPM
                        | TpmaObject::FIXED_PARENT,
                    auth_policy: Tpm2bDigest::default(),
                    parameters: TpmuPublicParms::Ecc {
                        symmetric: TpmtSymDefObject::default(),
                        scheme: TpmtScheme::default(),
                        curve_id,
                        kdf: TpmtKdfScheme::default(),
                    },
                    unique: TpmuPublicId::Ecc(TpmsEccPoint {
                        x: Tpm2bEccParameter::try_from(x)?,
                        y: Tpm2bEccParameter::try_from(y)?,
                    }),
                })
            }
            _ => unreachable!(),
        }
    }

    /// Returns raw private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the internal DER data is invalid.
    pub fn get_private_blob(&self) -> Result<&[u8], TpmError> {
        let private_key_info = PrivateKeyInfo::from_der(&self.private_key_info_der)
            .map_err(|e| TpmError::Parse(format!("DER parse error: {e}")))?;
        Ok(private_key_info.private_key)
    }
}

/// Convert ECC curve OID from DER `AnyRef` to TPM curve enum.
fn ec_oid_to_tpm_curve(any: &AnyRef) -> Result<TpmEccCurve, TpmError> {
    let der_bytes = any
        .to_der()
        .map_err(|e| TpmError::Parse(format!("DER error: {e}")))?;
    let oid = ObjectIdentifier::decode(&mut der::SliceReader::new(&der_bytes)?)
        .map_err(|_| TpmError::Parse("Invalid DER in ECC curve parameters".to_string()))?;

    match oid {
        SECP_256_R_1 => Ok(TpmEccCurve::NistP256),
        SECP_384_R_1 => Ok(TpmEccCurve::NistP384),
        SECP_521_R_1 => Ok(TpmEccCurve::NistP521),
        _ => Err(TpmError::Parse(format!("unsupported ECC curve OID: {oid}"))),
    }
}

/// TPM key ready for serialization or deserialization.
pub struct TpmKey {
    pub oid: Vec<u32>,
    pub parent: String,
    pub pub_key: Vec<u8>,
    pub priv_key: Vec<u8>,
}

impl TpmKey {
    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmError> {
        let der = self.to_der()?;
        Ok(pem::encode(&pem::Pem::new("TPM2 KEY", der)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmError> {
        let asn1 = TpmKeyAsn1 {
            oid: ObjectIdentifier::from_arcs(self.oid.iter().copied())
                .map_err(|e| TpmError::Parse(format!("OID encode error: {e:?}")))?,
            parent: u32::from_str_radix(self.parent.trim_start_matches("0x"), 16)
                .map_err(|e| TpmError::Parse(e.to_string()))?,
            pub_key: OctetString::new(self.pub_key.clone())?,
            priv_key: OctetString::new(self.priv_key.clone())?,
        };

        asn1.to_der()
            .map_err(|e| TpmError::Parse(format!("DER encode error: {e}")))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the PEM bytes cannot be parsed.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TpmError> {
        let pem = pem::parse(pem_bytes).map_err(|e| TpmError::Parse(e.to_string()))?;
        if pem.tag() != "TPM2 KEY" {
            return Err(TpmError::Parse("invalid PEM tag".to_string()));
        }
        Self::from_der(pem.contents())
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the DER bytes cannot be parsed into a valid `TpmKeyAsn1` data.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, TpmError> {
        let asn1 = TpmKeyAsn1::from_der(der_bytes)
            .map_err(|e| TpmError::Parse(format!("DER decode error: {e}")))?;

        Ok(TpmKey {
            oid: asn1.oid.arcs().collect(),
            parent: format!("{:#010x}", asn1.parent),
            pub_key: asn1.pub_key.as_bytes().to_vec(),
            priv_key: asn1.priv_key.as_bytes().to_vec(),
        })
    }
}

fn compute_hmac(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    attributes: u8,
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
    cp_hash_payload: &[u8],
) -> Result<Vec<u8>, TpmError> {
    macro_rules! do_hmac {
        ($digest:ty) => {{
            let cp_hash = <$digest as Digest>::digest(cp_hash_payload);
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(hmac_key)
                .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;
            mac.update(&cp_hash);
            mac.update(nonce_tpm);
            mac.update(nonce_caller);
            mac.update(&[attributes]);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match auth_hash {
        TpmAlgId::Sha256 => do_hmac!(Sha256),
        TpmAlgId::Sha384 => do_hmac!(Sha384),
        TpmAlgId::Sha512 => do_hmac!(Sha512),
        _ => Err(TpmError::Execution(format!(
            "unsupported session hash algorithm: {auth_hash}"
        ))),
    }
}

/// Computes the authorization HMAC for a command session.
///
/// # Errors
///
/// Returns a `TpmError::Execution` if the session's hash algorithm is not
/// supported, or if an HMAC operation fails.
pub fn create_auth(
    session: &super::AuthSession,
    nonce_caller: &tpm2_protocol::data::Tpm2bNonce,
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
) -> Result<TpmsAuthCommand, TpmError> {
    let cp_hash_payload = {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(command_code as u32).to_be_bytes());
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        payload.extend_from_slice(parameters);
        payload
    };

    let hmac_bytes = compute_hmac(
        session.auth_hash,
        &session.hmac_key,
        session.attributes.bits(),
        &session.nonce_tpm,
        nonce_caller,
        &cp_hash_payload,
    )?;

    Ok(TpmsAuthCommand {
        session_handle: session.handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: tpm2_protocol::data::Tpm2bAuth::try_from(hmac_bytes.as_slice())?,
    })
}

fn kdfa(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    label: &str,
    context_a: &[u8],
    context_b: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, TpmError> {
    let mut key_stream = Vec::new();
    let key_bytes = key_bits as usize / 8;

    macro_rules! do_kdfa_hmac {
        ($digest:ty) => {{
            let mut counter: u32 = 1;
            while key_stream.len() < key_bytes {
                let mut hmac = <Hmac<$digest> as Mac>::new_from_slice(hmac_key)
                    .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;

                hmac.update(&counter.to_be_bytes());
                hmac.update(label.as_bytes());
                hmac.update(&[0x00]);
                hmac.update(context_a);
                hmac.update(context_b);
                hmac.update(&u32::from(key_bits).to_be_bytes());

                let result = hmac.finalize().into_bytes();
                let remaining = key_bytes - key_stream.len();
                let to_take = remaining.min(result.len());
                key_stream.extend_from_slice(&result[..to_take]);

                counter += 1;
            }
        }};
    }

    match auth_hash {
        TpmAlgId::Sha256 => do_kdfa_hmac!(Sha256),
        TpmAlgId::Sha384 => do_kdfa_hmac!(Sha384),
        TpmAlgId::Sha512 => do_kdfa_hmac!(Sha512),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported hash algorithm for KDFa: {auth_hash}"
            )))
        }
    }

    Ok(key_stream)
}

/// Encrypts the import seed using the parent's RSA public key.
fn protect_seed_with_rsa(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2b), TpmError> {
    let n = match &parent_public.unique {
        TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
        _ => Err(TpmError::Execution(
            "parent is RSA type but unique field is not RSA".to_string(),
        )),
    }?;
    let e = match &parent_public.parameters {
        TpmuPublicParms::Rsa { exponent, .. } => Ok(*exponent),
        _ => Err(TpmError::Execution(
            "parent is RSA type but parameters field is not RSA".to_string(),
        )),
    }?;

    let rsa_pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_u32(e).ok_or_else(|| {
            TpmError::Execution("failed to convert exponent to BigUint".to_string())
        })?,
    )
    .map_err(|e| TpmError::Execution(format!("failed to construct RSA public key: {e}")))?;

    let mut rng = thread_rng();
    let parent_name_alg = parent_public.name_alg;
    let encrypted_seed_result = match parent_name_alg {
        TpmAlgId::Sha1 => rsa_pub_key.encrypt(&mut rng, Oaep::new::<Sha1>(), seed),
        TpmAlgId::Sha256 => rsa_pub_key.encrypt(&mut rng, Oaep::new::<Sha256>(), seed),
        TpmAlgId::Sha384 => rsa_pub_key.encrypt(&mut rng, Oaep::new::<Sha384>(), seed),
        TpmAlgId::Sha512 => rsa_pub_key.encrypt(&mut rng, Oaep::new::<Sha512>(), seed),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported parent nameAlg for RSA OAEP: {parent_name_alg:?}"
            )));
        }
    };
    let encrypted_seed = encrypted_seed_result
        .map_err(|e| TpmError::Execution(format!("RSA-OAEP encryption failed: {e}")))?;

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())?,
        Tpm2b::default(),
    ))
}

macro_rules! ecdh_protect_seed {
    (
        $parent_point:expr, $name_alg:expr, $seed:expr,
        $pk_ty:ty, $sk_ty:ty, $affine_ty:ty, $dh_fn:ident, $to_point_trait:ident, $curve_ty:ty, $encoded_point_ty:ty
    ) => {{
        let encoded_point = <$encoded_point_ty>::from_affine_coordinates(
            $parent_point.x.as_ref().into(),
            $parent_point.y.as_ref().into(),
            false,
        );
        let affine_point_opt: Option<$affine_ty> =
            <$affine_ty>::from_encoded_point(&encoded_point).into();
        let affine_point = affine_point_opt
            .ok_or_else(|| TpmError::Execution("Invalid parent public key".to_string()))?;

        let parent_pk = <$pk_ty>::from_affine(affine_point)
            .map_err(|e| TpmError::Execution(format!("failed to construct public key: {e}")))?;

        let ephemeral_sk = <$sk_ty>::random(&mut thread_rng());
        let shared_secret = $dh_fn(ephemeral_sk.to_nonzero_scalar(), parent_pk.as_affine());
        let z = shared_secret.raw_secret_bytes();
        let sym_material = kdfa($name_alg, z, "STORAGE", &[], &[], 256)?;
        let (aes_key, iv) = sym_material.split_at(16);
        let mut encrypted_seed_buf = *$seed;
        let mut cipher = Encryptor::<Aes128>::new(aes_key.into(), iv.into());
        let (block1, block2) = encrypted_seed_buf.split_at_mut(16);
        cipher.encrypt_block_mut(GenericArray::from_mut_slice(block1));
        cipher.encrypt_block_mut(GenericArray::from_mut_slice(block2));

        let pk_bytes = <$pk_ty as $to_point_trait<$curve_ty>>::to_encoded_point(
            &ephemeral_sk.public_key(),
            false,
        );
        (encrypted_seed_buf, pk_bytes.as_bytes().to_vec())
    }};
}

/// Encrypts the import seed using an ECDH shared secret derived from the parent's ECC public key.
fn protect_seed_with_ecc(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2b), TpmError> {
    let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
        (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc { curve_id, .. }) => Ok((point, *curve_id)),
        _ => Err(TpmError::Execution(
            "parent is not a valid ECC key".to_string(),
        )),
    }?;

    let (encrypted_seed, ephemeral_point_bytes) = match curve_id {
        TpmEccCurve::NistP256 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            p256::PublicKey,
            SecretKey,
            AffinePoint,
            diffie_hellman,
            ToEncodedPoint,
            p256::NistP256,
            p256::EncodedPoint
        ),
        TpmEccCurve::NistP384 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            PublicKey384,
            SecretKey384,
            AffinePoint384,
            p384_ecdh,
            ToEncodedPoint384,
            NistP384,
            p384::EncodedPoint
        ),
        TpmEccCurve::NistP521 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            PublicKey521,
            SecretKey521,
            AffinePoint521,
            p521_ecdh,
            ToEncodedPoint521,
            NistP521,
            p521::EncodedPoint
        ),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported parent ECC curve for import: {curve_id:?}"
            )))
        }
    };

    if ephemeral_point_bytes.is_empty() || ephemeral_point_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(TpmError::Execution(
            "invalid ephemeral ECC public key format".to_string(),
        ));
    }
    let coord_len = (ephemeral_point_bytes.len() - 1) / 2;
    let x = &ephemeral_point_bytes[1..=coord_len];
    let y = &ephemeral_point_bytes[1 + coord_len..];

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())?,
        Tpm2b::try_from(
            build_to_vec(&TpmsEccPoint {
                x: Tpm2bEccParameter::try_from(x)?,
                y: Tpm2bEccParameter::try_from(y)?,
            })?
            .as_slice(),
        )?,
    ))
}

/// Creates the encrypted blobs needed for `TPM2_Import`.
///
/// This function protects the sensitive private key material for import under a
/// parent key. It secures the seed used for symmetric encryption using the
/// parent's public key (RSA-OAEP for RSA parents, ECDH for ECC parents).
///
/// # Errors
///
/// Returns a `TpmError` for cryptographic failures or invalid input.
pub fn create_import_blob(
    parent_public: &TpmtPublic,
    object_alg: TpmAlgId,
    private_bytes: &[u8],
    parent_name: &[u8],
) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2b), TpmError> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    let parent_name_alg = parent_public.name_alg;

    let (in_sym_seed, encryption_key) = match parent_public.object_type {
        TpmAlgId::Rsa => protect_seed_with_rsa(parent_public, &seed)?,
        TpmAlgId::Ecc => protect_seed_with_ecc(parent_public, &seed)?,
        _ => {
            return Err(TpmError::Execution(
                "parent key must be RSA or ECC".to_string(),
            ))
        }
    };

    let parent_name_len_bytes = u16::try_from(parent_name.len())
        .map_err(|_| TpmError::Build(TpmErrorKind::InvalidValue))?
        .to_be_bytes();

    let sym_key = kdfa(
        parent_name_alg,
        &seed,
        "DUPLICATE",
        &parent_name_len_bytes,
        parent_name,
        128,
    )?;

    let integrity_key_bits = u16::try_from(
        tpm2_protocol::tpm_hash_size(&parent_name_alg).ok_or_else(|| {
            TpmError::Execution("parent nameAlg is not a supported hash".to_string())
        })? * 8,
    )
    .map_err(|_| TpmError::Execution("hash size conversion error".to_string()))?;

    let hmac_key = kdfa(
        parent_name_alg,
        &seed,
        "INTEGRITY",
        &parent_name_len_bytes,
        parent_name,
        integrity_key_bits,
    )?;

    let sensitive =
        tpm2_protocol::data::TpmtSensitive::from_private_bytes(object_alg, private_bytes)?;
    let sensitive_data_vec = build_to_vec(&sensitive)?;

    let mut enc_data = sensitive_data_vec;
    let iv = [0u8; 16];

    let mut cipher = Encryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    for chunk in enc_data.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block_mut(block);
    }

    macro_rules! do_integrity_hmac {
        ($digest:ty) => {{
            let mut integrity_mac = <Hmac<$digest> as Mac>::new_from_slice(&hmac_key)
                .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;
            integrity_mac.update(&enc_data);
            integrity_mac.update(parent_name);
            integrity_mac.finalize().into_bytes().to_vec()
        }};
    }

    let final_mac = match parent_name_alg {
        TpmAlgId::Sha256 => do_integrity_hmac!(Sha256),
        TpmAlgId::Sha384 => do_integrity_hmac!(Sha384),
        TpmAlgId::Sha512 => do_integrity_hmac!(Sha512),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported hash algorithm for integrity HMAC: {parent_name_alg}"
            )))
        }
    };

    let duplicate_blob = {
        let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
            Tpm2bDigest::try_from(final_mac.as_slice())?.build(&mut writer)?;
            writer.write_bytes(&enc_data)?;
            writer.len()
        };
        duplicate_blob_buf[..len].to_vec()
    };

    Ok((
        Tpm2bPrivate::try_from(duplicate_blob.as_slice())?,
        in_sym_seed,
        encryption_key,
    ))
}
