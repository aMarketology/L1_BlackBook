//! BlackBook L1 - TPS Benchmarks
//!
//! Criterion-based benchmarks for measuring transaction processing performance.
//!
//! Run: cargo bench --bench tps_benchmarks
//!
//! These benchmarks measure:
//! - PoH tick generation speed
//! - Sealevel parallel scheduling efficiency
//! - Ed25519 signature verification throughput
//! - ReDB storage read/write performance
//! - End-to-end transaction processing

use criterion::{
    criterion_group, criterion_main, Criterion, BenchmarkId, Throughput,
    black_box,
};
use std::time::{Duration, Instant};
use std::sync::Arc;

// We'll need to import the actual types from the crate
// For now, this is a template that shows the structure

// ============================================================================
// POH BENCHMARKS
// ============================================================================

/// Benchmark SHA-256 hash chain (PoH tick simulation)
fn bench_sha256_chain(c: &mut Criterion) {
    use sha2::{Digest, Sha256};
    
    let mut group = c.benchmark_group("PoH");
    
    // Single hash (one tick)
    group.bench_function("single_tick", |b| {
        let mut hash = [0u8; 32];
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hash = hasher.finalize().into();
            black_box(hash)
        });
    });
    
    // 1000 consecutive hashes (PoH segment)
    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000_ticks", |b| {
        b.iter(|| {
            let mut hash = [0u8; 32];
            for _ in 0..1000 {
                let mut hasher = Sha256::new();
                hasher.update(&hash);
                hash = hasher.finalize().into();
            }
            black_box(hash)
        });
    });
    
    // Transaction mix into PoH
    group.bench_function("tx_mix", |b| {
        let mut poh_hash = [0u8; 32];
        let tx_hash = [42u8; 32]; // Simulated transaction hash
        
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(&poh_hash);
            hasher.update(&tx_hash);
            poh_hash = hasher.finalize().into();
            black_box(poh_hash)
        });
    });
    
    group.finish();
}

// ============================================================================
// SIGNATURE VERIFICATION BENCHMARKS
// ============================================================================

fn bench_ed25519(c: &mut Criterion) {
    use ed25519_dalek::{SigningKey, Signer, Verifier};
    use rand::rngs::OsRng;
    
    let mut group = c.benchmark_group("Ed25519");
    
    // Generate a keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"BlackBook Transaction v2 - Benchmark";
    let signature = signing_key.sign(message);
    
    // Single verification
    group.bench_function("verify_single", |b| {
        b.iter(|| {
            black_box(verifying_key.verify(message, &signature))
        });
    });
    
    // Batch verification (sequential)
    for batch_size in [10, 100, 1000] {
        // Pre-generate signatures
        let signatures: Vec<_> = (0..batch_size)
            .map(|i| {
                let key = SigningKey::generate(&mut OsRng);
                let msg = format!("Transaction {}", i);
                let sig = key.sign(msg.as_bytes());
                (key.verifying_key(), msg, sig)
            })
            .collect();
        
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("verify_batch_seq", batch_size),
            &signatures,
            |b, sigs| {
                b.iter(|| {
                    let mut valid = 0u32;
                    for (vk, msg, sig) in sigs {
                        if vk.verify(msg.as_bytes(), sig).is_ok() {
                            valid += 1;
                        }
                    }
                    black_box(valid)
                });
            },
        );
    }
    
    // Parallel verification using rayon
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        
        for batch_size in [1000, 10000] {
            let signatures: Vec<_> = (0..batch_size)
                .map(|i| {
                    let key = SigningKey::generate(&mut OsRng);
                    let msg = format!("Transaction {}", i);
                    let sig = key.sign(msg.as_bytes());
                    (key.verifying_key(), msg, sig)
                })
                .collect();
            
            group.throughput(Throughput::Elements(batch_size as u64));
            group.bench_with_input(
                BenchmarkId::new("verify_batch_parallel", batch_size),
                &signatures,
                |b, sigs| {
                    b.iter(|| {
                        let valid: u32 = sigs.par_iter()
                            .filter(|(vk, msg, sig)| vk.verify(msg.as_bytes(), sig).is_ok())
                            .count() as u32;
                        black_box(valid)
                    });
                },
            );
        }
    }
    
    group.finish();
}

// ============================================================================
// PARALLEL SCHEDULING BENCHMARKS
// ============================================================================

/// Simulated transaction for scheduling tests
#[derive(Clone, Debug)]
struct MockTransaction {
    id: u64,
    from: String,
    to: String,
    amount: u64,
}

impl MockTransaction {
    fn new(id: u64, from: &str, to: &str) -> Self {
        Self {
            id,
            from: from.to_string(),
            to: to.to_string(),
            amount: 100,
        }
    }
    
    fn conflicts_with(&self, other: &Self) -> bool {
        self.from == other.from || self.from == other.to ||
        self.to == other.from || self.to == other.to
    }
}

fn bench_scheduling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sealevel_Scheduling");
    
    // Generate non-conflicting transactions (best case)
    fn gen_non_conflicting(count: usize) -> Vec<MockTransaction> {
        (0..count)
            .map(|i| MockTransaction::new(
                i as u64,
                &format!("BB_{:08x}", i * 2),
                &format!("BB_{:08x}", i * 2 + 1),
            ))
            .collect()
    }
    
    // Generate conflicting transactions (worst case - all touch same account)
    fn gen_conflicting(count: usize) -> Vec<MockTransaction> {
        (0..count)
            .map(|i| MockTransaction::new(
                i as u64,
                "BB_shared_account",
                &format!("BB_{:08x}", i),
            ))
            .collect()
    }
    
    // Schedule non-conflicting (best case)
    for tx_count in [100, 1_000, 10_000] {
        let txs = gen_non_conflicting(tx_count);
        
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("non_conflicting", tx_count),
            &txs,
            |b, transactions| {
                b.iter(|| {
                    let mut batches: Vec<Vec<&MockTransaction>> = vec![vec![]];
                    let batch_size = 256;
                    
                    for tx in transactions {
                        let current_batch = batches.last_mut().unwrap();
                        if current_batch.len() >= batch_size {
                            batches.push(vec![tx]);
                        } else {
                            current_batch.push(tx);
                        }
                    }
                    black_box(batches.len())
                });
            },
        );
    }
    
    // Schedule conflicting (worst case)
    for tx_count in [100, 1_000] {
        let txs = gen_conflicting(tx_count);
        
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("conflicting", tx_count),
            &txs,
            |b, transactions| {
                b.iter(|| {
                    let mut batches: Vec<Vec<&MockTransaction>> = vec![];
                    
                    for tx in transactions {
                        let mut placed = false;
                        
                        for batch in &mut batches {
                            let conflicts = batch.iter().any(|b_tx| tx.conflicts_with(b_tx));
                            if !conflicts && batch.len() < 256 {
                                batch.push(tx);
                                placed = true;
                                break;
                            }
                        }
                        
                        if !placed {
                            batches.push(vec![tx]);
                        }
                    }
                    black_box(batches.len())
                });
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// PARALLEL EXECUTION BENCHMARKS
// ============================================================================

fn bench_parallel_execution(c: &mut Criterion) {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use dashmap::DashMap;
    
    let mut group = c.benchmark_group("Sealevel_Execution");
    
    // Simulate balance updates (the core of transaction processing)
    let balances: Arc<DashMap<String, AtomicU64>> = Arc::new(DashMap::new());
    
    // Pre-populate 100K accounts
    for i in 0..100_000u64 {
        balances.insert(format!("BB_{:08x}", i), AtomicU64::new(1_000_000));
    }
    
    for tx_count in [1_000, 10_000, 50_000] {
        let txs: Vec<(String, String, u64)> = (0..tx_count)
            .map(|i| (
                format!("BB_{:08x}", i % 100_000),
                format!("BB_{:08x}", (i + 1) % 100_000),
                1u64,
            ))
            .collect();
        
        let balances_clone = balances.clone();
        
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("balance_updates", tx_count),
            &txs,
            |b, transactions| {
                b.iter(|| {
                    transactions.par_iter().for_each(|(from, to, amount)| {
                        // Debit
                        if let Some(from_bal) = balances_clone.get(from) {
                            from_bal.fetch_sub(*amount, Ordering::Relaxed);
                        }
                        // Credit
                        if let Some(to_bal) = balances_clone.get(to) {
                            to_bal.fetch_add(*amount, Ordering::Relaxed);
                        }
                    });
                    black_box(())
                });
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// STORAGE BENCHMARKS
// ============================================================================

fn bench_storage(c: &mut Criterion) {
    use dashmap::DashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    let mut group = c.benchmark_group("Storage");
    
    // DashMap (in-memory cache) benchmarks
    let cache: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
    
    // Write benchmark
    group.bench_function("dashmap_write", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            cache.insert(format!("BB_{:016x}", i), i * 1000);
            black_box(())
        });
    });
    
    // Pre-populate for reads
    for i in 0..100_000u64 {
        cache.insert(format!("BB_{:016x}", i), i * 1000);
    }
    
    // Read benchmark
    group.bench_function("dashmap_read", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i = (i + 1) % 100_000;
            let val = cache.get(&format!("BB_{:016x}", i));
            black_box(val)
        });
    });
    
    // Concurrent read/write mix (80% read, 20% write)
    use rayon::prelude::*;
    
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("dashmap_mixed_10k", |b| {
        b.iter(|| {
            (0..10_000u64).into_par_iter().for_each(|i| {
                if i % 5 == 0 {
                    // 20% writes
                    cache.insert(format!("BB_{:016x}", i + 100_000), i);
                } else {
                    // 80% reads
                    let _ = cache.get(&format!("BB_{:016x}", i % 100_000));
                }
            });
            black_box(())
        });
    });
    
    group.finish();
}

// ============================================================================
// END-TO-END TPS BENCHMARK
// ============================================================================

fn bench_e2e_tps(c: &mut Criterion) {
    use sha2::{Digest, Sha256};
    use dashmap::DashMap;
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    let mut group = c.benchmark_group("E2E_TPS");
    group.sample_size(10); // Fewer samples for long benchmarks
    group.measurement_time(Duration::from_secs(10));
    
    // Simulate full transaction pipeline
    let balances: Arc<DashMap<String, AtomicU64>> = Arc::new(DashMap::new());
    
    // Pre-populate 100K accounts
    for i in 0..100_000u64 {
        balances.insert(format!("BB_{:08x}", i), AtomicU64::new(1_000_000_000));
    }
    
    for tx_count in [1_000, 10_000, 50_000] {
        // Pre-generate transactions with "signatures"
        let transactions: Vec<(String, String, u64, [u8; 64])> = (0..tx_count)
            .map(|i| (
                format!("BB_{:08x}", i % 100_000),
                format!("BB_{:08x}", (i + 1) % 100_000),
                1u64,
                [0u8; 64], // Mock signature
            ))
            .collect();
        
        let balances_clone = balances.clone();
        
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("full_pipeline", tx_count),
            &transactions,
            |b, txs| {
                b.iter(|| {
                    // Stage 1: "Signature verification" (simulated)
                    let verified: Vec<_> = txs.par_iter()
                        .filter(|(_, _, _, sig)| {
                            // Simulate ~50μs verification
                            let mut hasher = Sha256::new();
                            hasher.update(sig);
                            let _ = hasher.finalize();
                            true
                        })
                        .collect();
                    
                    // Stage 2: Execute transfers
                    verified.par_iter().for_each(|(from, to, amount, _)| {
                        if let Some(from_bal) = balances_clone.get(from) {
                            from_bal.fetch_sub(*amount, Ordering::Relaxed);
                        }
                        if let Some(to_bal) = balances_clone.get(to) {
                            to_bal.fetch_add(*amount, Ordering::Relaxed);
                        }
                    });
                    
                    // Stage 3: Generate tx hashes for PoH
                    let _hashes: Vec<[u8; 32]> = verified.par_iter()
                        .map(|(from, to, amount, _)| {
                            let mut hasher = Sha256::new();
                            hasher.update(from.as_bytes());
                            hasher.update(to.as_bytes());
                            hasher.update(&amount.to_le_bytes());
                            hasher.finalize().into()
                        })
                        .collect();
                    
                    black_box(verified.len())
                });
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// MAX TPS DISCOVERY (Not a benchmark, but a standalone test)
// ============================================================================

/// Run this to find maximum TPS on current hardware
/// cargo test --release find_max_tps -- --nocapture
#[test]
#[ignore] // Run explicitly with --ignored
fn find_max_tps() {
    use sha2::{Digest, Sha256};
    use dashmap::DashMap;
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    println!("\n");
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║            BLACKBOOK L1 - MAX TPS DISCOVERY                    ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!("");
    println!("CPU Cores: {}", num_cpus::get());
    println!("");
    
    let balances: Arc<DashMap<String, AtomicU64>> = Arc::new(DashMap::new());
    
    // Pre-populate 1M accounts
    println!("Populating 1,000,000 accounts...");
    for i in 0..1_000_000u64 {
        balances.insert(format!("BB_{:08x}", i), AtomicU64::new(1_000_000_000));
    }
    println!("Done.\n");
    
    println!("Testing transaction batches...\n");
    println!("{:>12} | {:>10} | {:>12}", "Batch Size", "Time (ms)", "TPS");
    println!("{:-<12}-+-{:-<10}-+-{:-<12}", "", "", "");
    
    for batch_size in [1_000, 5_000, 10_000, 25_000, 50_000, 75_000, 100_000, 150_000, 200_000] {
        // Generate transactions
        let transactions: Vec<(String, String, u64)> = (0..batch_size)
            .map(|i| (
                format!("BB_{:08x}", i % 1_000_000),
                format!("BB_{:08x}", (i + 500) % 1_000_000),
                1u64,
            ))
            .collect();
        
        let balances_clone = balances.clone();
        
        // Time the processing
        let start = Instant::now();
        
        // Parallel execution
        transactions.par_iter().for_each(|(from, to, amount)| {
            // Simulate signature check
            let mut hasher = Sha256::new();
            hasher.update(from.as_bytes());
            let _ = hasher.finalize();
            
            // Execute transfer
            if let Some(from_bal) = balances_clone.get(from) {
                from_bal.fetch_sub(*amount, Ordering::Relaxed);
            }
            if let Some(to_bal) = balances_clone.get(to) {
                to_bal.fetch_add(*amount, Ordering::Relaxed);
            }
        });
        
        let elapsed = start.elapsed();
        let tps = batch_size as f64 / elapsed.as_secs_f64();
        
        println!("{:>12} | {:>10.2} | {:>12.0}", 
                 batch_size, 
                 elapsed.as_secs_f64() * 1000.0, 
                 tps);
        
        // Stop if batch takes too long
        if elapsed.as_secs() > 5 {
            println!("\n⚠️  Stopping - batch took > 5 seconds");
            break;
        }
    }
    
    println!("\n════════════════════════════════════════════════════════════════\n");
}

// ============================================================================
// CRITERION GROUPS
// ============================================================================

criterion_group!(
    benches,
    bench_sha256_chain,
    bench_ed25519,
    bench_scheduling,
    bench_parallel_execution,
    bench_storage,
    bench_e2e_tps,
);

criterion_main!(benches);
