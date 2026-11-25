//! QENC CLI - Command-line interface for post-quantum encrypted containers.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::or_fun_call,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::option_if_let_else,
    clippy::multiple_crate_versions,
)]

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::time::Instant;
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use humantime::format_duration;
use qenc_core::{
    encrypt_stream, decrypt_stream, inspect_header,
    EncryptOptions, DecryptOptions, CompressionProfile, KeyMode, ProgressEvent, ProgressStage,
};

#[derive(Parser)]
#[command(name = "qenc", version, about = "Post-Quantum Encrypted Container (.qenc)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt files or directories to a .qenc container
    Encrypt {
        /// Input files or directories
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,

        /// Output .qenc file
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption mode
        #[arg(short, long, value_enum, default_value = "passphrase")]
        mode: CliKeyMode,

        /// Compression profile
        #[arg(short, long, value_enum, default_value = "balanced")]
        profile: CliCompressionProfile,

        /// Recipient public key file (for PQC mode)
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Passphrase (for passphrase mode)
        #[arg(long)]
        passphrase: Option<String>,

        /// Passphrase from file (first line)
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Show progress bar
        #[arg(short, long, default_value = "true")]
        progress: bool,
    },

    /// Decrypt a .qenc container to a directory
    Decrypt {
        /// Input .qenc file
        input: PathBuf,

        /// Output directory
        #[arg(short, long)]
        output: PathBuf,

        /// Secret key file (for PQC mode)
        #[arg(long)]
        seckey: Option<PathBuf>,

        /// Passphrase (for passphrase mode)
        #[arg(long)]
        passphrase: Option<String>,

        /// Passphrase from file (first line)
        #[arg(long)]
        passphrase_file: Option<PathBuf>,

        /// Passphrase for decrypting the secret key file
        #[arg(long)]
        seckey_passphrase: Option<String>,

        /// Show progress bar
        #[arg(short, long, default_value = "true")]
        progress: bool,
    },

    /// Inspect a .qenc file header without decrypting
    Inspect {
        /// Input .qenc file
        input: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate a new Hybrid PQC keypair
    Keygen {
        /// Output prefix (generates <prefix>.qenc.pub and <prefix>.qenc.sec)
        #[arg(short, long)]
        output: PathBuf,

        /// Passphrase to encrypt the secret key
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Benchmark encryption/decryption performance
    Bench {
        /// Size in MB for test data
        #[arg(long, default_value = "16")]
        size_mb: usize,

        /// Number of iterations
        #[arg(long, default_value = "3")]
        iterations: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliKeyMode {
    Passphrase,
    Pqc,
}

impl From<CliKeyMode> for KeyMode {
    fn from(m: CliKeyMode) -> Self {
        match m {
            CliKeyMode::Passphrase => Self::Passphrase,
            CliKeyMode::Pqc => Self::HybridPqc,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliCompressionProfile {
    Turbo,
    Balanced,
    Ultra,
}

impl From<CliCompressionProfile> for CompressionProfile {
    fn from(p: CliCompressionProfile) -> Self {
        match p {
            CliCompressionProfile::Turbo => Self::Turbo,
            CliCompressionProfile::Balanced => Self::Balanced,
            CliCompressionProfile::Ultra => Self::Ultra,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { inputs, output, mode, profile, pubkey, passphrase, passphrase_file, progress } => {
            let passphrase = get_passphrase(passphrase, passphrase_file)?;
            let mode: KeyMode = mode.into();
            let profile: CompressionProfile = profile.into();

            // Validate inputs exist
            for input in &inputs {
                if !input.exists() {
                    anyhow::bail!("Input does not exist: {}", input.display());
                }
            }

            // Validate mode-specific args
            if mode == KeyMode::HybridPqc && pubkey.is_none() {
                anyhow::bail!("--pubkey required for PQC mode");
            }

            let options = EncryptOptions {
                mode,
                profile,
                passphrase,
                recipient_pubkey_path: pubkey.map(|p| p.to_string_lossy().into()),
                progress_cb: if progress { Some(Box::new(create_progress_callback())) } else { None },
                cancel: None,
                original_size_hint: None,
                argon2_mobile_hint: None,
            };

            println!("Encrypting {} item(s) to {}...", inputs.len(), output.display());
            let start = Instant::now();
            encrypt_stream(&inputs, BufWriter::new(File::create(&output)?), options)?;
            println!("Done in {}", format_duration(start.elapsed()));
        }

        Commands::Decrypt { input, output, seckey, passphrase, passphrase_file, seckey_passphrase, progress } => {
            let passphrase = get_passphrase(passphrase, passphrase_file)?;

            if !input.exists() {
                anyhow::bail!("Input file does not exist: {}", input.display());
            }

            let seckey_passphrase = get_passphrase(seckey_passphrase, None)?;
            let input_size_hint = std::fs::metadata(&input).ok().map(|m| m.len());
            let options = DecryptOptions {
                passphrase,
                secret_key_path: seckey.map(|p| p.to_string_lossy().into()),
                secret_key_passphrase: seckey_passphrase,
                progress_cb: if progress { Some(Box::new(create_progress_callback())) } else { None },
                cancel: None,
                input_size_hint,
            };

            println!("Decrypting {} to {}...", input.display(), output.display());
            let start = Instant::now();
            decrypt_stream(BufReader::new(File::open(&input)?), &output, options)?;
            println!("Done in {}", format_duration(start.elapsed()));
        }

        Commands::Inspect { input, json } => {
            if !input.exists() {
                anyhow::bail!("Input file does not exist: {}", input.display());
            }

            let mut file = File::open(&input)?;
            let metadata = inspect_header(&mut file)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&metadata)?);
            } else {
                print_metadata(&metadata);
            }
        }

        Commands::Keygen { output, passphrase } => {
            println!("Generating Hybrid PQC keypair (X25519 + ML-KEM-1024)...");
            // Generate the FULL keypair so the saved .qenc.sec contains the complete
            // ML-KEM-1024 decapsulation key and can actually decrypt .qenc files.
            let (public, secret) = qenc_core::crypto::generate_full_hybrid_keypair()?;

            let pub_path = output.with_extension("qenc.pub");
            let sec_path = output.with_extension("qenc.sec");

            qenc_core::crypto::save_public_key(&pub_path, &public)?;
            qenc_core::crypto::save_full_secret_key(&sec_path, &secret, passphrase.as_deref())?;

            println!("Public key saved to: {}", pub_path.display());
            println!("Secret key saved to: {}", sec_path.display());
            if passphrase.is_some() {
                println!("Secret key is encrypted with passphrase.");
            } else {
                println!("WARNING: Secret key is NOT encrypted!");
            }
        }

        Commands::Bench { size_mb, iterations } => {
            run_benchmark(size_mb, iterations)?;
        }
    }

    Ok(())
}

fn get_passphrase(passphrase: Option<String>, passphrase_file: Option<PathBuf>) -> anyhow::Result<Option<String>> {
    match (passphrase, passphrase_file) {
        (Some(p), None) => Ok(Some(p)),
        (None, Some(f)) => {
            let content = std::fs::read_to_string(f)?;
            Ok(Some(content.lines().next().unwrap_or("").to_string()))
        }
        (Some(_), Some(_)) => anyhow::bail!("Cannot specify both --passphrase and --passphrase-file"),
        (None, None) => Ok(None),
    }
}

fn create_progress_callback() -> Box<dyn Fn(ProgressEvent) + Send> {
    let multi = MultiProgress::new();
    let pb = multi.add(ProgressBar::new(0));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
        .unwrap()
        .progress_chars("##-"));

    Box::new(move |event: ProgressEvent| {
        let stage_str = match event.stage {
            ProgressStage::KeyDerivation => "Deriving Key",
            ProgressStage::Archiving => "Archiving",
            ProgressStage::Compressing => "Compressing",
            ProgressStage::Encrypting => "Encrypting",
            ProgressStage::Decrypting => "Decrypting",
            ProgressStage::Decompressing => "Decompressing",
            ProgressStage::Extracting => "Extracting",
            ProgressStage::Finalizing => "Finalizing",
        };

        if let Some(total) = event.total_bytes {
            pb.set_length(total);
            pb.set_position(event.bytes_processed);
        }
        pb.set_message(format!("{} | {:.1} MB/s", stage_str, event.mb_per_sec));
    })
}

fn print_metadata(metadata: &qenc_core::QencMetadata) {
    println!("=== QENC Container Metadata ===");
    println!("Version:           {}", metadata.version);
    println!("Key Mode:          {:?}", metadata.key_mode);
    println!("Compression:       {:?}", metadata.compression_profile);
    println!("Chunk Size:        {} bytes ({} MiB)", metadata.chunk_size, metadata.chunk_size / 1_048_576);
    println!("Original Size:     {} bytes ({:.2} MiB)", metadata.original_size, metadata.original_size as f64 / 1_048_576.0);

    if let Some(params) = &metadata.argon2_params {
        println!("Argon2id Params:");
        println!("  Memory Cost:     {} KiB ({:.1} MiB)", params.m_cost_kib, f64::from(params.m_cost_kib) / 1024.0);
        println!("  Time Cost:       {}", params.t_cost);
        println!("  Parallelism:     {}", params.p_cost);
    }

    if let Some(pk) = &metadata.ephemeral_x25519_pk {
        println!("Ephemeral X25519 PK: {}", hex::encode(pk));
    }

    if let Some(ct) = &metadata.mlkem_ciphertext {
        println!("ML-KEM-1024 Ciphertext: {} bytes", ct.len());
    }
}

fn run_benchmark(size_mb: usize, iterations: usize) -> anyhow::Result<()> {
    use std::fs;
    use tempfile::TempDir;

    println!("=== QENC Benchmark ===");
    println!("Test data size: {size_mb} MB");
    println!("Iterations: {iterations}");
    println!();

    let test_data_size = size_mb * 1_048_576;
    let profiles = [
        ("Turbo", CompressionProfile::Turbo),
        ("Balanced", CompressionProfile::Balanced),
        ("Ultra", CompressionProfile::Ultra),
    ];

    for (name, profile) in profiles {
        println!("--- {name} Profile ---");

        let mut encrypt_times = Vec::new();
        let mut decrypt_times = Vec::new();
        let mut compressed_sizes = Vec::new();

        for i in 0..iterations {
            let temp = TempDir::new()?;
            let input_file = temp.path().join("bench.bin");
            let output_file = temp.path().join("bench.qenc");
            let decrypt_dir = temp.path().join("out");

            // Generate random test data
            let mut data = vec![0u8; test_data_size];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut data);
            fs::write(&input_file, &data)?;

            // Encrypt
            let start = Instant::now();
            let options = EncryptOptions {
                mode: KeyMode::Passphrase,
                profile,
                passphrase: Some("benchmark passphrase".into()),
                ..Default::default()
            };
            encrypt_stream(&[&input_file], BufWriter::new(File::create(&output_file)?), options)?;
            let encrypt_time = start.elapsed();
            encrypt_times.push(encrypt_time);

            let compressed_size = fs::metadata(&output_file)?.len();
            compressed_sizes.push(compressed_size);

            // Decrypt
            let start = Instant::now();
            let decrypt_options = DecryptOptions {
                passphrase: Some("benchmark passphrase".into()),
                ..Default::default()
            };
            decrypt_stream(BufReader::new(File::open(&output_file)?), &decrypt_dir, decrypt_options)?;
            let decrypt_time = start.elapsed();
            decrypt_times.push(decrypt_time);

            // Verify
            let extracted = decrypt_dir.join("bench.bin");
            assert_eq!(fs::read(extracted)?, data);

            println!("  Iteration {}: enc={:.2}s dec={:.2}s ratio={:.2}%", i + 1,
                encrypt_time.as_secs_f64(),
                decrypt_time.as_secs_f64(),
                compressed_size as f64 / test_data_size as f64 * 100.0
            );
        }

        // Average results
        let avg_encrypt = encrypt_times.iter().sum::<std::time::Duration>() / iterations as u32;
        let avg_decrypt = decrypt_times.iter().sum::<std::time::Duration>() / iterations as u32;
        let avg_compressed = compressed_sizes.iter().sum::<u64>() / iterations as u64;
        let ratio = avg_compressed as f64 / test_data_size as f64 * 100.0;
        let enc_throughput = test_data_size as f64 / 1_048_576.0 / avg_encrypt.as_secs_f64();
        let dec_throughput = test_data_size as f64 / 1_048_576.0 / avg_decrypt.as_secs_f64();

        println!("  Average: enc={:.2}s dec={:.2}s ratio={:.1}% enc_throughput={:.1} MB/s dec_throughput={:.1} MB/s",
            avg_encrypt.as_secs_f64(),
            avg_decrypt.as_secs_f64(),
            ratio,
            enc_throughput,
            dec_throughput
        );
        println!();
    }

    Ok(())
}