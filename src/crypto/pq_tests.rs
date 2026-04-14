//! Comprehensive tests for post-quantum cryptography support.
//!
//! These tests verify the functionality of ML-DSA-65, ML-KEM-768, and hybrid
//! signature modes, as well as their integration with the license system.
//!
//! Run with: `cargo test --features post-quantum`

#![cfg(feature = "post-quantum")]

use crate::crypto::{
    algorithm_ids, hybrid::HybridEd25519MlDsaSigner, ml_dsa::MlDsa65Signer, ml_kem::MlKem768Kem,
    CryptoKeyPair, CryptoRegistry, SignatureAlgorithm,
};

// ============================================================================
// ML-DSA-65 Tests
// ============================================================================

mod ml_dsa_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_registry_integration() {
        let alg = CryptoRegistry::get_signature_algorithm(algorithm_ids::ML_DSA_65).unwrap();
        assert_eq!(alg.algorithm_id(), "ML-DSA-65");
    }

    #[test]
    fn test_ml_dsa_65_keypair_via_registry() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        assert_eq!(keypair.algorithm_id, algorithm_ids::ML_DSA_65);
        assert!(keypair.private_key_pem().contains("ML-DSA-65 PRIVATE KEY"));
        assert!(keypair.public_key_pem.contains("ML-DSA-65 PUBLIC KEY"));
    }

    #[test]
    fn test_ml_dsa_65_sign_verify_via_registry() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

        let data = b"License data to sign with post-quantum algorithm";
        let signature = keypair.sign(data).unwrap();

        // Verify signature size is in expected range
        // ML-DSA-65 signatures are 3309 bytes
        assert!(
            signature.len() > 3200,
            "ML-DSA-65 signature should be ~3309 bytes"
        );
        assert!(signature.len() < 3400);

        // Verify the signature
        assert!(keypair.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_different_data_fails() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

        let data = b"Original data";
        let signature = keypair.sign(data).unwrap();

        let different_data = b"Modified data";
        assert!(keypair.verify(different_data, &signature).is_err());
    }

    #[test]
    fn test_ml_dsa_65_cross_key_fails() {
        let keypair1 = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let keypair2 = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

        let data = b"Test data";
        let signature = keypair1.sign(data).unwrap();

        // Using keypair2's public key should fail
        assert!(keypair2.verify(data, &signature).is_err());
    }

    #[test]
    fn test_ml_dsa_65_key_sizes() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        // Private key is stored as a 32-byte seed (compact representation)
        assert!(
            private_pem.len() > 50,
            "ML-DSA-65 private key PEM should contain a seed"
        );
        assert!(
            private_pem.contains("ML-DSA-65 PRIVATE KEY"),
            "ML-DSA-65 private key should have correct PEM tag"
        );
        // Public key should be ~1952 bytes raw
        assert!(
            public_pem.len() > 2500,
            "ML-DSA-65 public key PEM should be large"
        );
    }

    #[test]
    fn test_ml_dsa_65_deterministic_verification() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

        let data = b"Consistent verification test";
        let signature = keypair.sign(data).unwrap();

        // Verify multiple times - should always succeed
        for _ in 0..10 {
            assert!(keypair.verify(data, &signature).is_ok());
        }
    }
}

// ============================================================================
// ML-KEM-768 Tests
// ============================================================================

mod ml_kem_tests {
    use super::*;
    use crate::crypto::ml_kem::{decrypt_with_kem, encrypt_with_kem, sizes};

    #[test]
    fn test_ml_kem_768_key_generation() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        assert!(private_pem.contains("ML-KEM-768 PRIVATE KEY"));
        assert!(public_pem.contains("ML-KEM-768 PUBLIC KEY"));
    }

    #[test]
    fn test_ml_kem_768_encapsulation_roundtrip() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        // Encapsulate multiple times - each should produce different shared secrets
        let (secret1, ct1) = kem.encapsulate(&public_pem).unwrap();
        let (secret2, ct2) = kem.encapsulate(&public_pem).unwrap();

        // Secrets should be different (IND-CCA2 security)
        assert_ne!(secret1, secret2);
        assert_ne!(ct1, ct2);

        // But decapsulation should recover the correct secrets
        let recovered1 = kem.decapsulate(&ct1, &private_pem).unwrap();
        let recovered2 = kem.decapsulate(&ct2, &private_pem).unwrap();

        assert_eq!(secret1, recovered1);
        assert_eq!(secret2, recovered2);
    }

    #[test]
    fn test_ml_kem_768_shared_secret_size() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();

        let (secret, _) = kem.encapsulate(&public_pem).unwrap();

        assert_eq!(secret.len(), 32, "ML-KEM shared secret should be 32 bytes");
    }

    #[test]
    fn test_ml_kem_768_hybrid_encryption() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"This is sensitive license payload data!";

        let encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kem(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ml_kem_768_encryption_different_ciphertext() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"Same plaintext";

        // Encrypt twice - ciphertexts should be different (randomized)
        let ct1 = encrypt_with_kem(plaintext, &public_pem).unwrap();
        let ct2 = encrypt_with_kem(plaintext, &public_pem).unwrap();

        assert_ne!(ct1, ct2, "Encryption should be randomized");
    }

    #[test]
    fn test_ml_kem_768_wrong_key_decryption_fails() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();
        let (other_private_pem, _) = kem.generate_keypair().unwrap();

        let plaintext = b"Secret data";
        let encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();

        // Decryption with wrong key should fail (AES-GCM authentication)
        let result = decrypt_with_kem(&encrypted, &other_private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_768_tampered_ciphertext_fails() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"Important data";
        let mut encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();

        // Tamper with the ciphertext
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        // Decryption should fail
        let result = decrypt_with_kem(&encrypted, &private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_768_large_payload_encryption() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        // Encrypt a large payload (simulating a complex license)
        let plaintext = vec![0xAB; 100_000];

        let encrypted = encrypt_with_kem(&plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kem(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ml_kem_768_sizes() {
        assert_eq!(sizes::public_key_bytes(), 1184);
        assert_eq!(sizes::ciphertext_bytes(), 1088);
        assert_eq!(sizes::shared_secret_bytes(), 32);
    }
}

// ============================================================================
// Hybrid Signature Tests
// ============================================================================

mod hybrid_tests {
    use super::*;

    #[test]
    fn test_hybrid_rsa_ml_dsa_registry() {
        let alg =
            CryptoRegistry::get_signature_algorithm(algorithm_ids::HYBRID_RSA_ML_DSA_65).unwrap();
        assert_eq!(alg.algorithm_id(), "Hybrid-RSA-ML-DSA-65");
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_registry() {
        let alg = CryptoRegistry::get_signature_algorithm(algorithm_ids::HYBRID_ED25519_ML_DSA_65)
            .unwrap();
        assert_eq!(alg.algorithm_id(), "Hybrid-Ed25519-ML-DSA-65");
    }

    #[test]
    fn test_hybrid_rsa_ml_dsa_sign_verify() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_RSA_ML_DSA_65).unwrap();

        let data = b"Hybrid signed data";
        let signature = keypair.sign(data).unwrap();

        // Signature should contain RSA (~384 bytes for 3072-bit) + ML-DSA-65 (~3309 bytes) + header
        assert!(signature.len() > 3500);

        assert!(keypair.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_sign_verify() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();

        let data = b"Hybrid signed data";
        let signature = keypair.sign(data).unwrap();

        // Signature should contain Ed25519 (64 bytes) + ML-DSA-65 (~3309 bytes) + header
        assert!(signature.len() > 3300);
        assert!(signature.len() < 3500);

        assert!(keypair.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_hybrid_cross_key_fails() {
        let keypair1 = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let keypair2 = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();

        let data = b"Test data";
        let signature = keypair1.sign(data).unwrap();

        assert!(keypair2.verify(data, &signature).is_err());
    }

    #[test]
    fn test_hybrid_modified_data_fails() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();

        let data = b"Original data";
        let signature = keypair.sign(data).unwrap();

        let modified = b"Modified data";
        assert!(keypair.verify(modified, &signature).is_err());
    }

    #[test]
    fn test_hybrid_tampered_classical_sig_fails() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        // Tamper with classical signature (bytes 4-67 for Ed25519)
        if signature.len() > 10 {
            signature[10] ^= 0xFF;
        }

        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_tampered_pq_sig_fails() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        // Tamper with PQ signature (last bytes)
        let last = signature.len() - 1;
        signature[last] ^= 0xFF;

        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_both_parts_required() {
        // This test verifies that both signature components must be valid
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Important data";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Truncate the signature to remove PQ part
        let truncated = &signature[..100]; // Only classical part

        assert!(signer.verify(data, truncated, &public_pem).is_err());
    }
}

// ============================================================================
// Registry and Feature Tests
// ============================================================================

mod registry_tests {
    use super::*;

    #[test]
    fn test_post_quantum_available() {
        assert!(CryptoRegistry::is_post_quantum_available());
    }

    #[test]
    fn test_pq_algorithms_in_supported_list() {
        let supported = CryptoRegistry::supported_signature_algorithms();

        assert!(supported.contains(&"ML-DSA-65"));
        assert!(supported.contains(&"Hybrid-RSA-ML-DSA-65"));
        assert!(supported.contains(&"Hybrid-Ed25519-ML-DSA-65"));
    }

    #[test]
    fn test_post_quantum_algorithm_list() {
        let pq_algs = CryptoRegistry::post_quantum_signature_algorithms();

        assert!(pq_algs.contains(&"ML-DSA-65"));
        assert!(pq_algs.contains(&"Hybrid-RSA-ML-DSA-65"));
        assert!(pq_algs.contains(&"Hybrid-Ed25519-ML-DSA-65"));
        assert_eq!(pq_algs.len(), 3);
    }

    #[test]
    fn test_hybrid_algorithm_list() {
        let hybrid_algs = CryptoRegistry::hybrid_signature_algorithms();

        assert!(hybrid_algs.contains(&"Hybrid-RSA-ML-DSA-65"));
        assert!(hybrid_algs.contains(&"Hybrid-Ed25519-ML-DSA-65"));
        assert!(!hybrid_algs.contains(&"ML-DSA-65")); // Not hybrid
        assert_eq!(hybrid_algs.len(), 2);
    }

    #[test]
    fn test_classical_algorithm_list() {
        let classical_algs = CryptoRegistry::classical_signature_algorithms();

        assert!(classical_algs.contains(&"RSA-SHA256"));
        assert!(classical_algs.contains(&"Ed25519"));
        assert!(!classical_algs.contains(&"ML-DSA-65")); // Not classical
        assert_eq!(classical_algs.len(), 2);
    }

    #[test]
    fn test_recommended_algorithm_is_hybrid() {
        let recommended = CryptoRegistry::recommended_algorithm();

        // With post-quantum enabled, should recommend hybrid
        assert_eq!(recommended.algorithm_id(), "Hybrid-Ed25519-ML-DSA-65");
    }
}

// ============================================================================
// Interoperability Tests
// ============================================================================

mod interop_tests {
    use super::*;

    #[test]
    fn test_different_algorithms_incompatible() {
        // Generate keys with different algorithms
        let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let data = b"Test data";

        // Sign with ML-DSA-65
        let ml_dsa_sig = ml_dsa_keypair.sign(data).unwrap();

        // Try to verify with Ed25519 - should fail
        assert!(ed25519_keypair.verify(data, &ml_dsa_sig).is_err());

        // Sign with Ed25519
        let ed25519_sig = ed25519_keypair.sign(data).unwrap();

        // Try to verify with ML-DSA-65 - should fail
        assert!(ml_dsa_keypair.verify(data, &ed25519_sig).is_err());
    }

    #[test]
    fn test_hybrid_incompatible_with_pure_algorithms() {
        let hybrid_keypair =
            CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let data = b"Test data";
        let hybrid_sig = hybrid_keypair.sign(data).unwrap();

        // Neither pure algorithm can verify hybrid signatures
        assert!(ml_dsa_keypair.verify(data, &hybrid_sig).is_err());
        assert!(ed25519_keypair.verify(data, &hybrid_sig).is_err());
    }

    #[test]
    fn test_extract_public_key_consistency() {
        // Test that extract_public_key produces consistent results
        // for algorithms that support it (hybrid modes)
        for alg_id in CryptoRegistry::hybrid_signature_algorithms() {
            let alg = CryptoRegistry::get_signature_algorithm(alg_id).unwrap();
            let (private_pem, public_pem) = alg.generate_keypair().unwrap();

            let extracted = alg.extract_public_key(&private_pem).unwrap();
            assert_eq!(
                extracted, public_pem,
                "Extracted public key should match for {}",
                alg_id
            );

            // Verify that both keys work for verification
            let data = b"Consistency test";
            let signature = alg.sign(data, &private_pem).unwrap();

            assert!(alg.verify(data, &signature, &public_pem).is_ok());
            assert!(alg.verify(data, &signature, &extracted).is_ok());
        }
    }
}

// ============================================================================
// Performance Comparison Tests (informational)
// ============================================================================

mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_signature_sizes_comparison() {
        let data = b"License payload for size comparison";

        // Ed25519
        let ed_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let ed_sig = ed_keypair.sign(data).unwrap();

        // ML-DSA-65
        let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let ml_dsa_sig = ml_dsa_keypair.sign(data).unwrap();

        // Hybrid Ed25519 + ML-DSA-65
        let hyb_keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let hyb_sig = hyb_keypair.sign(data).unwrap();

        println!("\n=== Signature Size Comparison ===");
        println!("Ed25519:                    {} bytes", ed_sig.len());
        println!("ML-DSA-65:                  {} bytes", ml_dsa_sig.len());
        println!("Hybrid Ed25519+ML-DSA-65:   {} bytes", hyb_sig.len());

        // Verify sizes are reasonable
        assert_eq!(ed_sig.len(), 64);
        assert!(ml_dsa_sig.len() > 3200 && ml_dsa_sig.len() < 3400);
        assert!(hyb_sig.len() > 3300 && hyb_sig.len() < 3500);
    }

    #[test]
    fn test_key_sizes_comparison() {
        // Ed25519
        let ed_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        // ML-DSA-65
        let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

        // Hybrid
        let hyb_keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();

        println!("\n=== Key Size Comparison (PEM, approximate) ===");
        println!(
            "Ed25519 private:          {} bytes",
            ed_keypair.private_key_pem().len()
        );
        println!(
            "Ed25519 public:           {} bytes",
            ed_keypair.public_key_pem.len()
        );
        println!(
            "ML-DSA-65 private:        {} bytes",
            ml_dsa_keypair.private_key_pem().len()
        );
        println!(
            "ML-DSA-65 public:         {} bytes",
            ml_dsa_keypair.public_key_pem.len()
        );
        println!(
            "Hybrid private:           {} bytes",
            hyb_keypair.private_key_pem().len()
        );
        println!(
            "Hybrid public:            {} bytes",
            hyb_keypair.public_key_pem.len()
        );
    }

    #[test]
    #[ignore] // Run with `cargo test --features post-quantum -- --ignored` for benchmarks
    fn test_performance_comparison() {
        let iterations = 100;
        let data = b"Performance test payload for license signing";

        // Ed25519
        let ed_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ed_keypair.sign(data).unwrap();
        }
        let ed_sign_time = start.elapsed();

        let ed_sig = ed_keypair.sign(data).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            ed_keypair.verify(data, &ed_sig).unwrap();
        }
        let ed_verify_time = start.elapsed();

        // ML-DSA-65
        let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ml_dsa_keypair.sign(data).unwrap();
        }
        let ml_dsa_sign_time = start.elapsed();

        let ml_dsa_sig = ml_dsa_keypair.sign(data).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            ml_dsa_keypair.verify(data, &ml_dsa_sig).unwrap();
        }
        let ml_dsa_verify_time = start.elapsed();

        // Hybrid
        let hyb_keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = hyb_keypair.sign(data).unwrap();
        }
        let hyb_sign_time = start.elapsed();

        let hyb_sig = hyb_keypair.sign(data).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            hyb_keypair.verify(data, &hyb_sig).unwrap();
        }
        let hyb_verify_time = start.elapsed();

        println!(
            "\n=== Performance Comparison ({} iterations) ===",
            iterations
        );
        println!(
            "Ed25519 sign:      {:?} ({:?}/op)",
            ed_sign_time,
            ed_sign_time / iterations as u32
        );
        println!(
            "Ed25519 verify:    {:?} ({:?}/op)",
            ed_verify_time,
            ed_verify_time / iterations as u32
        );
        println!(
            "ML-DSA-65 sign:    {:?} ({:?}/op)",
            ml_dsa_sign_time,
            ml_dsa_sign_time / iterations as u32
        );
        println!(
            "ML-DSA-65 verify:  {:?} ({:?}/op)",
            ml_dsa_verify_time,
            ml_dsa_verify_time / iterations as u32
        );
        println!(
            "Hybrid sign:       {:?} ({:?}/op)",
            hyb_sign_time,
            hyb_sign_time / iterations as u32
        );
        println!(
            "Hybrid verify:     {:?} ({:?}/op)",
            hyb_verify_time,
            hyb_verify_time / iterations as u32
        );
    }
}

// ============================================================================
// License Integration Tests
// ============================================================================

mod license_integration_tests {
    use super::*;

    /// Simulates the license signing and verification flow
    #[test]
    fn test_license_signing_flow_with_ml_dsa() {
        // Simulate license data
        let license_json = r#"{
            "id": "lic-123",
            "customer": "ACME Corp",
            "product": "Enterprise",
            "expires": "2025-12-31"
        }"#;

        // Sign with ML-DSA-65
        let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
        let signature = keypair.sign(license_json.as_bytes()).unwrap();

        // Verify
        assert!(keypair.verify(license_json.as_bytes(), &signature).is_ok());

        // Tampered license should fail
        let tampered = license_json.replace("2025", "2099");
        assert!(keypair.verify(tampered.as_bytes(), &signature).is_err());
    }

    /// Simulates the license signing and verification flow with hybrid
    #[test]
    fn test_license_signing_flow_with_hybrid() {
        let license_json = r#"{
            "id": "lic-456",
            "customer": "Quantum Corp",
            "product": "Quantum-Safe",
            "features": ["pq-crypto", "hybrid-mode"]
        }"#;

        // Sign with hybrid algorithm
        let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let signature = keypair.sign(license_json.as_bytes()).unwrap();

        // Verify
        assert!(keypair.verify(license_json.as_bytes(), &signature).is_ok());
    }

    /// Tests encrypting license data with ML-KEM
    #[test]
    fn test_license_encryption_with_ml_kem() {
        use crate::crypto::ml_kem::{decrypt_with_kem, encrypt_with_kem, MlKem768Kem};

        // Generate ML-KEM keys for the license server
        let kem = MlKem768Kem::new();
        let (private_key, public_key) = kem.generate_keypair().unwrap();

        // License data that needs to be protected
        let license_data = r#"{
            "secret_key": "abc123",
            "activation_limit": 5,
            "hardware_ids": ["hw-001", "hw-002"]
        }"#;

        // Encrypt with the server's public key
        let encrypted = encrypt_with_kem(license_data.as_bytes(), &public_key).unwrap();

        // Verify encrypted data is different from plaintext
        assert_ne!(&encrypted[..], license_data.as_bytes());

        // Decrypt with the server's private key
        let decrypted = decrypt_with_kem(&encrypted, &private_key).unwrap();

        assert_eq!(decrypted, license_data.as_bytes());
    }

    /// Tests the complete workflow: sign and encrypt
    #[test]
    fn test_complete_pq_license_workflow() {
        use crate::crypto::ml_kem::{decrypt_with_kem, encrypt_with_kem, MlKem768Kem};

        // Server-side: Generate signing and encryption keys
        let signing_keypair =
            CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
        let kem = MlKem768Kem::new();
        let (kem_private, kem_public) = kem.generate_keypair().unwrap();

        // Create license data
        let license = r#"{"customer":"Test","expires":"2025-12-31"}"#;

        // Sign the license
        let signature = signing_keypair.sign(license.as_bytes()).unwrap();

        // Create signed license bundle
        let bundle = format!(
            "{}|{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, license),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature)
        );

        // Encrypt the bundle for transport
        let encrypted = encrypt_with_kem(bundle.as_bytes(), &kem_public).unwrap();

        // Client-side: Decrypt and verify
        let decrypted_bundle = decrypt_with_kem(&encrypted, &kem_private).unwrap();
        let bundle_str = String::from_utf8(decrypted_bundle).unwrap();

        let parts: Vec<&str> = bundle_str.split('|').collect();
        let decoded_license =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[0]).unwrap();
        let decoded_sig =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[1]).unwrap();

        // Verify signature
        assert!(signing_keypair
            .verify(&decoded_license, &decoded_sig)
            .is_ok());

        // Verify license content
        assert_eq!(decoded_license, license.as_bytes());
    }
}
