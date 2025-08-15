// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use tpm2_protocol::{
    data::{
        self, Tpm2bPublic, Tpm2bSensitiveCreate, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRh,
        TpmSe, TpmSt, TpmaAlgorithm, TpmaLocality, TpmaObject, TpmaSession, TpmiYesNo,
        TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsCreationData,
        TpmsEccPoint, TpmsKeyedhashParms, TpmsPcrSelection, TpmsSensitiveCreate,
        TpmsSymcipherParms, TpmtHa, TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDef,
        TpmtTkCreation, TpmtTkHashcheck, TpmuCapabilities, TpmuHa, TpmuPublicId, TpmuPublicParms,
        TpmuSensitiveComposite, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{
        TpmCommandBody, TpmContextLoadCommand, TpmContextSaveCommand, TpmCreateCommand,
        TpmCreatePrimaryCommand, TpmDictionaryAttackLockResetCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHashCommand,
        TpmImportCommand, TpmLoadCommand, TpmPcrEventCommand, TpmPcrReadCommand,
        TpmPcrReadResponse, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmReadPublicCommand, TpmResponseBody, TpmStartAuthSessionCommand,
        TpmUnsealCommand,
    },
    TpmBuffer, TpmList, TpmPersistent, TpmSession, TpmTransient,
};
use tracing::trace;

const INDENT: usize = 2;

pub trait PrettyTrace {
    fn pretty_trace(&self, name: &str, indent: usize);
}

macro_rules! pretty_trace {
    ($type:ty, $format:literal) => {
        impl PrettyTrace for $type {
            fn pretty_trace(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                trace!(
                    target: "cli::device",
                    "{prefix}{name}: {value}",
                    prefix = prefix,
                    name = name,
                    value = format_args!($format, self)
                );
            }
        }
    };
}

pretty_trace!(u8, "{:#04x}");
pretty_trace!(u16, "{:#06x}");
pretty_trace!(u32, "{:#010x}");
pretty_trace!(u64, "{:#018x}");
pretty_trace!(i32, "{}");
pretty_trace!(TpmAlgId, "{}");
pretty_trace!(TpmCc, "{}");
pretty_trace!(TpmRh, "{}");
pretty_trace!(TpmCap, "{}");
pretty_trace!(TpmSe, "{:?}");
pretty_trace!(TpmSt, "{:?}");
pretty_trace!(TpmEccCurve, "{:?}");
pretty_trace!(TpmaObject, "{:?}");
pretty_trace!(TpmaAlgorithm, "{:?}");
pretty_trace!(TpmaSession, "{:?}");
pretty_trace!(TpmaLocality, "{:?}");
pretty_trace!(TpmiYesNo, "{:?}");
pretty_trace!(TpmTransient, "{:#010x}");
pretty_trace!(TpmPersistent, "{:#010x}");
pretty_trace!(TpmSession, "{:#010x}");

impl<const CAPACITY: usize> PrettyTrace for TpmBuffer<CAPACITY> {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(
            target: "cli::device",
            "{}{}: (size={}) {}",
            prefix,
            name,
            self.len(),
            hex::encode(self)
        );
    }
}

impl<T, const CAPACITY: usize> PrettyTrace for TpmList<T, CAPACITY>
where
    T: PrettyTrace + Copy + Default,
{
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}: (count={})", prefix, name, self.len());
        for item in self.iter() {
            item.pretty_trace("", indent + 1);
        }
    }
}

macro_rules! pretty_trace_struct {
    ($type:ty, $($field:ident => $name:literal),* $(,)?) => {
        impl PrettyTrace for $type {
            fn pretty_trace(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                if !name.is_empty() {
                    trace!(target: "cli::device", "{}{}:", prefix, name);
                }
                #[allow(unused_variables)]
                let field_indent = if name.is_empty() { indent } else { indent + 1 };
                $(
                    self.$field.pretty_trace($name, field_indent);
                )*
            }
        }
    };
}

pretty_trace_struct!(TpmsAlgProperty, alg => "alg", alg_properties => "algProperties");
pretty_trace_struct!(TpmsPcrSelection, hash => "hash", pcr_select => "pcrSelect");
pretty_trace_struct!(TpmsKeyedhashParms, scheme => "scheme");
pretty_trace_struct!(TpmsSymcipherParms, sym => "sym");
pretty_trace_struct!(TpmtKdfScheme, scheme => "scheme");
pretty_trace_struct!(TpmtScheme, scheme => "scheme");
pretty_trace_struct!(TpmsEccPoint, x => "x", y => "y");
pretty_trace_struct!(TpmsContext, sequence => "sequence", saved_handle => "savedHandle", hierarchy => "hierarchy", context_blob => "contextBlob");
pretty_trace_struct!(TpmsAuthCommand, session_handle => "sessionHandle", nonce => "nonce", session_attributes => "sessionAttributes", hmac => "hmac");
pretty_trace_struct!(TpmsSensitiveCreate, user_auth => "userAuth", data => "data");
pretty_trace_struct!(TpmtTkCreation, tag => "tag", hierarchy => "hierarchy", digest => "digest");
pretty_trace_struct!(TpmtTkHashcheck, tag => "tag", hierarchy => "hierarchy", digest => "digest");
pretty_trace_struct!(
    TpmsCreationData,
    pcr_select => "pcrSelect",
    pcr_digest => "pcrDigest",
    locality => "locality",
    parent_name_alg => "parentNameAlg",
    parent_name => "parentName",
    parent_qualified_name => "parentQualifiedName",
    outside_info => "outsideInfo",
);

pretty_trace_struct!(TpmGetCapabilityCommand, cap => "cap", property => "property", property_count => "propertyCount");
pretty_trace_struct!(TpmHashCommand, data => "data", hash_alg => "hashAlg", hierarchy => "hierarchy");
pretty_trace_struct!(TpmPcrReadCommand, pcr_selection_in => "pcrSelectionIn");
pretty_trace_struct!(TpmUnsealCommand,);
pretty_trace_struct!(TpmStartAuthSessionCommand, nonce_caller => "nonceCaller", encrypted_salt => "encryptedSalt", session_type => "sessionType", symmetric => "symmetric", auth_hash => "authHash");
pretty_trace_struct!(TpmPolicyGetDigestCommand,);
pretty_trace_struct!(TpmPolicySecretCommand, nonce_tpm => "nonceTpm", cp_hash_a => "cpHashA", policy_ref => "policyRef", expiration => "expiration");
pretty_trace_struct!(TpmPolicyOrCommand, p_hash_list => "pHashList");
pretty_trace_struct!(TpmPolicyPcrCommand, pcr_digest => "pcrDigest", pcrs => "pcrs");
pretty_trace_struct!(TpmDictionaryAttackLockResetCommand,);
pretty_trace_struct!(TpmEvictControlCommand, persistent_handle => "persistentHandle");
pretty_trace_struct!(TpmContextSaveCommand,);
pretty_trace_struct!(TpmContextLoadCommand, context => "context");
pretty_trace_struct!(TpmFlushContextCommand, flush_handle => "flushHandle");
pretty_trace_struct!(TpmLoadCommand, in_private => "inPrivate", in_public => "inPublic");
pretty_trace_struct!(TpmCreateCommand, in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
pretty_trace_struct!(TpmCreatePrimaryCommand, in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
pretty_trace_struct!(TpmImportCommand, encryption_key => "encryptionKey", object_public => "objectPublic", duplicate => "duplicate", in_sym_seed => "inSymSeed", symmetric_alg => "symmetricAlg");
pretty_trace_struct!(TpmReadPublicCommand,);
pretty_trace_struct!(TpmPcrEventCommand, event_data => "eventData");

pretty_trace_struct!(Tpm2bPublic, inner => "inner");
pretty_trace_struct!(Tpm2bSensitiveCreate, inner => "inner");
pretty_trace_struct!(data::Tpm2bCreationData, inner => "inner");

impl PrettyTrace for TpmuHa {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(
            target: "cli::device",
            "{}{}: (size={}) {}",
            prefix,
            name,
            self.len(),
            hex::encode(&**self)
        );
    }
}

impl PrettyTrace for TpmtHa {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}:", prefix, name);
        self.hash_alg.pretty_trace("hashAlg", indent + 1);
        self.digest.pretty_trace("digest", indent + 1);
    }
}

impl PrettyTrace for TpmsCapabilityData {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}:", prefix, name);
        self.capability.pretty_trace("capability", indent + 1);
        self.data.pretty_trace("data", indent + 1);
    }
}

impl PrettyTrace for TpmuCapabilities {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::Algs(algs) => algs.pretty_trace(name, indent),
            Self::Handles(handles) => handles.pretty_trace(name, indent),
            Self::Pcrs(pcrs) => pcrs.pretty_trace(name, indent),
        }
    }
}

impl PrettyTrace for TpmtPublic {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}:", prefix, name);
        self.object_type.pretty_trace("type", indent + 1);
        self.name_alg.pretty_trace("nameAlg", indent + 1);
        self.object_attributes
            .pretty_trace("objectAttributes", indent + 1);
        self.auth_policy.pretty_trace("authPolicy", indent + 1);
        self.parameters.pretty_trace("parameters", indent + 1);
        self.unique.pretty_trace("unique", indent + 1);
    }
}

impl PrettyTrace for TpmuPublicId {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(b) => b.pretty_trace(&format!("{name} (keyedHash)"), indent),
            Self::SymCipher(b) => b.pretty_trace(&format!("{name} (sym)"), indent),
            Self::Rsa(b) => b.pretty_trace(&format!("{name} (rsa)"), indent),
            Self::Ecc(p) => p.pretty_trace(&format!("{name} (ecc)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmuPublicParms {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash { details } => {
                details.pretty_trace(&format!("{name} (keyedHash)"), indent);
            }
            Self::SymCipher { details } => details.pretty_trace(&format!("{name} (sym)"), indent),
            Self::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            } => {
                trace!(target: "cli::device", "{prefix}{name}: (rsa)");
                symmetric.pretty_trace("symmetric", indent + 1);
                scheme.pretty_trace("scheme", indent + 1);
                key_bits.pretty_trace("keyBits", indent + 1);
                exponent.pretty_trace("exponent", indent + 1);
            }
            Self::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            } => {
                trace!(target: "cli::device", "{prefix}{name}: (ecc)");
                symmetric.pretty_trace("symmetric", indent + 1);
                scheme.pretty_trace("scheme", indent + 1);
                curve_id.pretty_trace("curveId", indent + 1);
                kdf.pretty_trace("kdf", indent + 1);
            }
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmtSymDef {
    fn pretty_trace(&self, name: &str, indent: usize) {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.pretty_trace(name, indent);
        } else {
            let prefix = " ".repeat(indent * INDENT);
            trace!(target: "cli::device", "{}{}:", prefix, name);
            self.algorithm.pretty_trace("algorithm", indent + 1);
            self.key_bits.pretty_trace("keyBits", indent + 1);
            self.mode.pretty_trace("mode", indent + 1);
        }
    }
}

impl PrettyTrace for TpmuSymKeyBits {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.pretty_trace(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.pretty_trace(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.pretty_trace(&format!("{name} (camellia)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmuSymMode {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.pretty_trace(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.pretty_trace(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.pretty_trace(&format!("{name} (camellia)"), indent),
            Self::Xor | Self::Null => trace!(target: "cli::device", "{prefix}{name}: {:?}" , self),
        }
    }
}

impl PrettyTrace for TpmuSensitiveComposite {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::Rsa(b) => b.pretty_trace(&format!("{name} (rsa)"), indent),
            Self::Ecc(b) => b.pretty_trace(&format!("{name} (ecc)"), indent),
            Self::Bits(b) => b.pretty_trace(&format!("{name} (bits)"), indent),
            Self::Sym(b) => b.pretty_trace(&format!("{name} (sym)"), indent),
        }
    }
}

pretty_trace_struct!(TpmGetCapabilityResponse, more_data => "moreData", capability_data => "capabilityData");
pretty_trace_struct!(TpmPcrReadResponse, pcr_update_counter => "pcrUpdateCounter", pcr_selection_out => "pcrSelectionOut", pcr_values => "pcrValues");

impl PrettyTrace for TpmCommandBody {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::GetCapability(cmd) => cmd.pretty_trace(name, indent),
            Self::PcrRead(cmd) => cmd.pretty_trace(name, indent),
            Self::Hash(cmd) => cmd.pretty_trace(name, indent),
            Self::Unseal(cmd) => cmd.pretty_trace(name, indent),
            Self::StartAuthSession(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyGetDigest(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicySecret(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyOr(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyPcr(cmd) => cmd.pretty_trace(name, indent),
            Self::DictionaryAttackLockReset(cmd) => cmd.pretty_trace(name, indent),
            Self::EvictControl(cmd) => cmd.pretty_trace(name, indent),
            Self::ContextSave(cmd) => cmd.pretty_trace(name, indent),
            Self::ContextLoad(cmd) => cmd.pretty_trace(name, indent),
            Self::FlushContext(cmd) => cmd.pretty_trace(name, indent),
            Self::Load(cmd) => cmd.pretty_trace(name, indent),
            Self::Create(cmd) => cmd.pretty_trace(name, indent),
            Self::CreatePrimary(cmd) => cmd.pretty_trace(name, indent),
            Self::Import(cmd) => cmd.pretty_trace(name, indent),
            Self::ReadPublic(cmd) => cmd.pretty_trace(name, indent),
            Self::PcrEvent(cmd) => cmd.pretty_trace(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {:?} (unimplemented pretty trace)", self);
            }
        }
    }
}

impl PrettyTrace for TpmResponseBody {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::GetCapability(resp) => resp.pretty_trace(name, indent),
            Self::PcrRead(resp) => resp.pretty_trace(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {:?} (unimplemented pretty trace)", self);
            }
        }
    }
}
