use anyhow::{anyhow, Result};
use clap::{clap_app, crate_authors, crate_description, crate_version, value_t, Arg};
use derive_more::Display;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::time::SystemTime;
use std::{env, fs};

mod vault;
use vault::{SignatureOps, Vault};

const AFTER_HELP: &str = "NOTE:
    The vaultsign CLI implements just enough of the full GPG CLI interface
    for happy-path git sign and verify operations to function correctly.";

// The GPG status protocol is described fully here: https://git.io/JURc9
//
// The gist is that when the `--status-fd` argument is passed, GPG will output
// machine-readable status updates to that fd. The `git` CLI uses the
// `--status-fd` in very set ways during sign and verify operations, and these
// set ways are all that are catered for in this CLI.

/// Demarcates a GPG status protocol line.
const GPG_MARKER: &str = "[GNUPG:]";

/// Encapsulates the subset of the GPG status protocol needed for git sign and
/// verify operations.
enum GPGStatus<'a> {
    /// BEGIN_SIGNING
    ///
    /// Mark the start of the actual signing process. This may be used as an
    /// indication that all requested secret keys are ready for use.
    BeginSigning,
    /// SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <keyfpr>
    ///
    /// A signature has been created using these parameters.
    /// Values for type <type> are:
    ///   - D :: detached
    ///   - C :: cleartext
    ///   - S :: standard
    /// (only the first character should be checked)
    ///
    /// <class> are 2 hex digits with the OpenPGP signature class.
    ///
    /// Note, that TIMESTAMP may either be a number of seconds since Epoch or an
    /// ISO 8601 string which can be detected by the presence of the letter 'T'.
    SigCreated(&'a str),
    /// NEWSIG [<signers_uid>]
    ///
    /// Is issued right before a signature verification starts. This is useful
    /// to define a context for parsing ERROR status messages. arguments are
    /// currently defined. If SIGNERS_UID is given and is not "-" this is the
    /// percent escape value of the OpenPGP Signer's User ID signature
    /// sub-packet.
    NewSig,
    /// GOODSIG  <long_keyid_or_fpr>  <username>
    ///
    /// The signature with the keyid is good. For each signature only one of the
    /// codes GOODSIG, BADSIG, EXPSIG, EXPKEYSIG, REVKEYSIG or ERRSIG will be
    /// emitted. In the past they were used as a marker for a new signature; new
    /// code should use the NEWSIG status instead. The username is the primary
    /// one encoded in UTF-8 and %XX escaped. The fingerprint may be used
    /// instead of the long keyid if it is available. This is the case with CMS
    /// and might eventually also be available for OpenPGP.
    GoodSig(&'a str),
    /// BADSIG <long_keyid_or_fpr> <username>
    ///
    /// The signature with the keyid has not been verified okay. The username is
    /// the primary one encoded in UTF-8 and %XX escaped. The fingerprint may be
    /// used instead of the long keyid if it is available. This is the case with
    /// CMS and might eventually also be available for OpenPGP.
    BadSig(&'a str),
    /// TRUST_
    /// These are several similar status codes:
    ///
    /// - TRUST_UNDEFINED <error_token>
    /// - TRUST_NEVER     <error_token>
    /// - TRUST_MARGINAL  [0  [<validation_model>]]
    /// - TRUST_FULLY     [0  [<validation_model>]]
    /// - TRUST_ULTIMATE  [0  [<validation_model>]]
    ///
    /// For good signatures one of these status lines are emitted to
    /// indicate the validity of the key used to create the signature.
    /// The error token values are currently only emitted by gpgsm.
    ///
    /// VALIDATION_MODEL describes the algorithm used to check the
    /// validity of the key.  The defaults are the standard Web of Trust
    /// model for gpg and the standard X.509 model for gpgsm.  The
    /// defined values are
    ///
    ///    - pgp   :: The standard PGP WoT.
    ///    - shell :: The standard X.509 model.
    ///    - chain :: The chain model.
    ///    - steed :: The STEED model.
    ///    - tofu  :: The TOFU model
    ///
    /// Note that the term =TRUST_= in the status names is used for
    /// historic reasons; we now speak of validity.
    TrustFully,
}

impl GPGStatus<'_> {
    fn emit(&self, status: &mut GPGWriter) -> Result<()> {
        match self {
            GPGStatus::NewSig => writeln!(status, "{} NEWSIG", GPG_MARKER),
            GPGStatus::GoodSig(fpr) => writeln!(status, "{} GOODSIG {}", GPG_MARKER, fpr),
            GPGStatus::BadSig(fpr) => writeln!(status, "{} BADSIG {}", GPG_MARKER, fpr),
            GPGStatus::TrustFully => writeln!(status, "{} TRUST_FULLY 0 shell", GPG_MARKER),
            GPGStatus::BeginSigning => writeln!(status, "{} BEGIN_SIGNING", GPG_MARKER),
            GPGStatus::SigCreated(fpr) => writeln!(
                status,
                "{} SIG_CREATED D - - 0 {} {}",
                GPG_MARKER,
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                fpr
            ),
        }
        .map_err(|e| anyhow!("status: {}", e))
    }
}

/// A writer type alias used for GPG status or output.
type GPGWriter = Box<dyn Write>;

/// Signals the beginning of GPG ASCII-armored signature bytes.
const GPG_SIG_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
/// Signals the end of GPG ASCII-armored signature bytes.
const GPG_SIG_END: &str = "-----END PGP SIGNATURE-----";

#[derive(Display)]
pub struct GPGSignature(String);

impl GPGSignature {
    // Constructs an internal representation of a signature.
    fn new(sig: String) -> Self {
        Self(
            sig.lines()
                .filter(|l| {
                    !l.is_empty() && !l.starts_with(GPG_SIG_BEGIN) && !l.starts_with(GPG_SIG_END)
                })
                .collect(),
        )
    }

    // Reads the signature from a file.
    fn new_from_file(file: PathBuf) -> Result<Self> {
        Ok(GPGSignature::new(fs::read_to_string(file)?))
    }

    // Writes the signature to the output in GPG ASCII-armored format.
    fn emit(&self, output: &mut GPGWriter) -> Result<()> {
        Ok(writeln!(
            output,
            "{}\n{}\n{}",
            GPG_SIG_BEGIN, self.0, GPG_SIG_END
        )?)
    }
}

/// Encapsulates the subset of the GPG actions needed for git sign and verify
/// operations.
#[derive(Debug)]
pub enum Action {
    Sign,
    Verify,
}

impl Action {
    pub fn from_args(args: &clap::ArgMatches) -> Result<Self> {
        if args.is_present("sign") {
            Ok(Action::Sign)
        } else if args.is_present("verify") {
            Ok(Action::Verify)
        } else {
            // Unreachable due to being required on the clap group.
            Err(anyhow!("unsupported action"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // SSL certificate locations on the system for OpenSSL.
    openssl_probe::init_ssl_cert_env_vars();

    let args = clap_app!(vaultsign =>
        // As above, we are not implementing the full GPG CLI interface here,
        // rather, just enough for git sign and verify operations. We therefore
        // force very specific argument combinations, rejecting everything else.
        (@group action +required =>
         (@arg sign: -s --sign requires[armor local_user detach_sign] "Make a signature")
         (@arg verify: -v --verify "Verify a signature")
        )
        (@arg detach_sign: -b --("detach-sign") requires[sign] "Make a detached signature")
        (@arg armor: -a --armor requires[sign] "Create ASCII armored output")
        (@arg local_user: -u --("local-user") +takes_value requires[sign] "USER-ID to sign or decrypt")
        (@arg FILE: ... {|s: String| {
                if s == "-" || Path::new(&s).exists() {
                    Ok(())
                } else {
                    Err(String::from("File or path does not exist"))
                }
            }
        })
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (after_help: AFTER_HELP)
    )
    .arg(Arg::with_name("keyid_format")
        .long("keyid-format")
        .takes_value(true)
        .requires("verify")
        .possible_values(&["long"])
        .help("Select how to display key IDs"))
    .arg(Arg::with_name("status_fd")
        .long("status-fd")
        .takes_value(true)
        .possible_values(&["1", "2"])
        .help("Write special status strings to the file descriptor n."))
    // Mandatory Vault related arguments.
    .arg(Arg::with_name("vault_addr")
        .long("vault_addr")
        .env("VAULT_ADDR")
        .hide_env_values(true)
        .default_value("http://127.0.0.1:8200")
        .help("Vault address to use for sign and verify actions"))
    .arg(Arg::with_name("vault_sig_path")
        .long("vault_sign_path")
        .env("VAULT_SIGN_PATH")
        .hide_env_values(true)
        .default_value("transit/sign/test/sha2-256")
        .help("The Vault path to use for sign actions"))
    .arg(Arg::with_name("vault_ver_path")
        .long("vault_verify_path")
        .env("VAULT_VERIFY_PATH")
        .hide_env_values(true)
        .default_value("transit/verify/test")
        .help("The Vault path to use for verify actions"))
    .get_matches();

    // Get the status file descriptor and produce writers for status and output.
    // NOTE: The `status_fd` arg is guaranteed to be 1 or 2 from the clap group.
    let (mut status, mut output) = if value_t!(args.value_of("status_fd"), u32)? == 1 {
        (
            Box::new(stdout()) as GPGWriter,
            Box::new(stderr()) as GPGWriter,
        )
    } else {
        (
            Box::new(stderr()) as GPGWriter,
            Box::new(stdout()) as GPGWriter,
        )
    };

    // Build a Vault client from the environment or CLI args.
    // NOTE: unwraps fine as the defaults are guaranteed from clap parse.
    let vault_addr = args.value_of("vault_addr").unwrap();
    let vault_sig_path = args.value_of("vault_sig_path").unwrap();
    let vault_ver_path = args.value_of("vault_ver_path").unwrap();
    let vault = Vault::new(vault_addr, vault_sig_path, vault_ver_path)?;

    match Action::from_args(&args)? {
        Action::Sign => {
            // Read the data to be signed from stdin.
            let mut data = String::new();
            stdin().read_to_string(&mut data)?;

            // Indicate our signing intentions on the status output.
            GPGStatus::BeginSigning.emit(&mut status)?;

            // And sign the data using Vault.
            match vault.sign(data).await {
                Ok(sig) => {
                    GPGSignature::new(sig).emit(&mut output)?;
                    GPGStatus::SigCreated(&[vault_addr, vault_sig_path].join("/"))
                        .emit(&mut status)?;

                    Ok(())
                }
                Err(e) => {
                    writeln!(output, "vault: signing failed")?;
                    writeln!(output, "vault: {:?}", e)?;

                    Err(e)
                }
            }
        }
        Action::Verify => {
            // Read the GPG ASCII-armored signature file.
            // NOTE: file existence guaranteed from clap parse.
            let sig =
                GPGSignature::new_from_file(value_t!(args.value_of("FILE"), PathBuf)?)?.to_string();

            // And the data to be verified from stdin.
            let mut data = String::new();
            stdin().read_to_string(&mut data)?;

            // Indicate our verification intentions on the status output.
            GPGStatus::NewSig.emit(&mut status)?;

            let fpr = &[vault_addr, vault_ver_path].join("/");
            writeln!(output, "vault: {}", fpr)?;

            // And verify the data and signature using Vault.
            match vault.verify(data, sig).await {
                Ok(()) => {
                    writeln!(output, "vault: verified")?;
                    GPGStatus::GoodSig(&fpr).emit(&mut status)?;
                    GPGStatus::TrustFully.emit(&mut status)?;

                    Ok(())
                }
                Err(e) => {
                    writeln!(output, "vault: {:?}", e)?;
                    writeln!(output, "vault: unverified")?;
                    GPGStatus::BadSig(&fpr).emit(&mut status)?;

                    Err(e)
                }
            }
        }
    }
}
