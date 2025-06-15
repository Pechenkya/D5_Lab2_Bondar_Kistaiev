#![allow(dead_code, non_snake_case)]
mod auxil;
use std::{collections::HashMap};
use rayon::prelude::*;
use std::time::Instant;


use crate::auxil::*;

// Substitution for Variant 2
const S_BLOCK: [u16; 16] = [0x8, 0x0, 0xC, 0x4, 0x9, 0x6, 0x7, 0xB, 0x2, 0x3, 0x1, 0xF, 0x5, 0xE, 0xA, 0xD];

// Inverted substitution
const S_INV:   [u16; 16] = [0x1, 0xA, 0x8, 0x9, 0x3, 0xC, 0x5, 0x6, 0x0, 0x4, 0xE, 0x7, 0x2, 0xF, 0xD, 0xB];

// Precomputed permutation table (Permytation will be the same for inverse)
static mut PERMUTATION_TABLE: [u16; 65536] = [0u16; 65536];
static mut SPERMUTATION_TABLE: [u16; 65536] = [0u16; 65536];
unsafe fn precalc_perm() {
    for x in 0u16..=65535u16 {
        for i in 0..=3 {
            PERMUTATION_TABLE[usize::from(x)] ^= ((((x >> (i * 4)) & 0b0001)) ^ 
                                                 ((((x >> (i * 4)) & 0b0010)) << 3) ^
                                                 ((((x >> (i * 4)) & 0b0100)) << 6) ^ 
                                                 ((((x >> (i * 4)) & 0b1000)) << 9)) << i;
        }
    }

    for x in 0u16..=65535u16 {        
        SPERMUTATION_TABLE[usize::from(x)] = PERMUTATION_TABLE[apply_substitution(x, &S_BLOCK) as usize];
    }
}

static mut ONE_DIM_TRANSLATE: [u16; 65536] = [0u16; 65536];
unsafe fn precalc_shlop() {
    for x in 0u16..=65535u16 {
        ONE_DIM_TRANSLATE[usize::from(x)] = (x.count_ones() as u16) % 2u16;
    }
}

// General function to apply substitution (4 bit blocks) for 16 bit value
fn apply_substitution(x: u16, S: &[u16; 16]) -> u16 {
    S[usize::from(x) & 0xF] ^
    S[usize::from(x >> 4) & 0xF] << 4 ^ 
    S[usize::from(x >> 8) & 0xF] << 8 ^
    S[usize::from(x >> 12)] << 12
}

// Permutation and substitution to calculate probs
fn spermutation(mut x: u16) -> u16 {
    // Substitution with inverse
    x = apply_substitution(x, &S_BLOCK);

    // Permutation
    unsafe {
        PERMUTATION_TABLE[x as usize]
    }
}

// Inverse permutation and substitution to get x ^ k
fn unspermutation(mut x: u16) -> u16 {
    // Permutation
    unsafe {
        x = PERMUTATION_TABLE[x as usize];
    }

    // Substitution with inverse
    apply_substitution(x, &S_INV)
}

// Heys round for 16 bit block
fn heys_round(mut x: u16, k: u16) -> u16 {
    // Adding the key
    x ^= k;

    // Substitution
    x = apply_substitution(x, &S_BLOCK);

    // Permutation
    unsafe {
        PERMUTATION_TABLE[x as usize]
    }
}

// Heys full encryption for 16 bit block
fn heys_encrypt(mut x: u16, k: [u16; 7]) -> u16 {
    // Six main rounds
    for i in 0..6 {
        x = heys_round(x, k[i]);
    }

    // Final blinding
    x ^= k[6];

    x
}

fn heys_encrypt_from_file(pt_path: &str, ct_path: &str, k_path: &str) {
    let data: Vec<u16> = read_bytes_from_file(pt_path).chunks_exact(2).map(|chunk| {
        bytes_to_u16(chunk.try_into().unwrap())
    }).collect();
    let keys: [u16; 7] = read_key(k_path);

    println!("Data: {:x?}", data.iter().map(|x| u16_to_bytes(*x)).collect::<Vec<_>>());
    println!("Keys: {:x?}", keys);

    let encrypted_data = data.iter().map(|&x| heys_encrypt(x, keys)).collect::<Vec<_>>();

    println!("Encrypted: {:x?}", encrypted_data.iter().map(|x| u16_to_bytes(*x)).collect::<Vec<_>>());
    write_bytes_to_file(ct_path, &encrypted_data.iter().map(|x| u16_to_bytes(*x)).collect::<Vec<_>>().concat());  
}

// Cryptoanalysis 
fn generate_lp_table() -> Vec<HashMap<u16, f32>> {
    let lp_table: Vec<HashMap<u16, f32>> = (0..=65535).into_par_iter()
        .map(|alph| { 
            println!("Started: {alph}");
            unsafe {
                (0..=65535).filter_map(|beta| {
                    let lp = ((65536. - 2. * ((0..=65535).map(|x| { ONE_DIM_TRANSLATE[(alph & x ^ beta & SPERMUTATION_TABLE[x as usize]) as usize] }).sum::<u16>() as f32)) / 65536.).powi(2);
                    if lp == 0f32 {
                        None
                    }
                    else {
                        Some((beta, lp))
                    }
                }).collect()
            }
        }).collect();

    lp_table
}


// fn branch_and_bound(alph: u16, r: usize, p_bound: f32, lp_table: &Vec<Vec<f32>>) -> HashMap<u16, f32> {
//     let mut Gamma_prev: HashMap<u16, f32> = Default::default();
//     Gamma_prev.insert(alph, 1.0);
//
//     for _ in 1..=r {
//         let mut Gamma_next: HashMap<u16, f32> = Default::default();
//         for (&beta, &p) in Gamma_prev.iter() {
//             for gamma in 0..=65535 {
//                 let q = lp_table[beta as usize][gamma as usize];
//
//                 if let Some(prob) = Gamma_next.get_mut(&gamma) {
//                     *prob += p * q;
//                 } else {
//                     Gamma_next.insert(gamma, p * q);
//                 }
//             }
//         }
//
//         Gamma_next.retain(|_, v| *v > p_bound);
//
//         Gamma_prev = Gamma_next;
//     };
//
//     Gamma_prev
// }

fn branch_and_bound(alph: u16, r: usize, p_bound: f32, dps_table: &Vec<HashMap<u16, f32>>) -> HashMap<u16, f32> {
    let mut Gamma_prev: HashMap<u16, f32> = Default::default();
    Gamma_prev.insert(alph, 1.0);

    for _ in 1..=r {
        let mut Gamma_next: HashMap<u16, f32> = Default::default();
        for (&beta, &p) in Gamma_prev.iter() {
            for (&gamma, &q) in dps_table[beta as usize].iter() {

                if let Some(prob) = Gamma_next.get_mut(&gamma) {
                    *prob += p * q;
                } else {
                    Gamma_next.insert(gamma, p * q);
                }
            }
        }

        Gamma_next.retain(|_, v| *v > p_bound);

        Gamma_prev = Gamma_next;
    };

    Gamma_prev
}

fn main() {
    unsafe {
        precalc_perm();
        precalc_shlop();
    }

    /* Calculate LP table */ 
    // let now = Instant::now();
    // let lp_table = generate_lp_table();
    // let elapsed = now.elapsed();
    // println!("Elapsed: {:.2?}", elapsed); // Elapsed: 15376.29s
    // save_Vec_Maps(&lp_table, "test_data/lp_table_saved.bin").unwrap();

    let now = Instant::now();
    let lp_table = load_Vec_Maps("test_data/lp_table_saved.bin").unwrap();
    let elapsed = now.elapsed();
    println!("Table loaded in: {:.2?}", elapsed);
 
    println!("LP Table ready!");

    /* .filter(|alpha| {(alpha & 0x000F != 0 && alpha & 0xFFF0 == 0) ||
                                                          (alpha & 0x00F0 != 0 && alpha & 0xFF0F == 0) ||
                                                          (alpha & 0x0F00 != 0 && alpha & 0xF0FF == 0) ||
                                                          (alpha & 0xF000 != 0 && alpha & 0x0FFF == 0)}) */

    let now = Instant::now();
    let corr_bound = 0.0002;    
    let res = (0..=65535).into_par_iter().map(|alpha| {
        let res = branch_and_bound(alpha, 5, corr_bound, &lp_table)
            .into_iter().filter(|(beta, _)| *beta != 0).collect::<HashMap<u16, f32>>();

        (alpha, res)
    }).collect::<Vec<_>>();
    let elapsed = now.elapsed();
    println!("B&B time: {:.2?}", elapsed);

    let top15 = res.iter().take(15).collect::<Vec<_>>();
    println!("15 elements in B&B result: {top15:?}");

    let mut pairs_to_prob: HashMap<(u16, u16), f32> = HashMap::new();
    for (alpha, beta_probs) in res.iter() {
        for (&beta, &prob) in beta_probs.iter() {
            pairs_to_prob.insert((*alpha, beta), prob);
        }
    }
    // println!("Combined HashMap: {pairs_to_prob:?}");

    // Select top 500 highest value pairs from pairs_to_prob
    let mut pairs_vec: Vec<(&(u16, u16), &f32)> = pairs_to_prob.iter().collect();
    pairs_vec.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
    let top_500 = pairs_vec.into_iter().take(500).collect::<Vec<_>>();
    // println!("Top 500 pairs: {:?}", top_500);

    let min_lp = top_500.last().unwrap().1;
    println!("Min LP: {:}", min_lp);

    let N = (4f32 / *min_lp) as usize;
    println!("Sample size: {N}");

    let samples = sample_random_bytes_from_file("test_data/open.txt", "test_data/cypher_own.txt", N);

    let keys = (0..=65535).map(|k| k as u16).collect::<Vec<_>>();
    let mut keys_candidates: HashMap<u16, u16> = HashMap::new();

    top_500.iter().for_each(|((alpha, beta), _lp)|{           
        let mut selected = keys.iter().map(|key| {
            let ka_kount = N as i64 - 2 * (samples.iter().map(|(plain, suffer)| { 
                unsafe { ONE_DIM_TRANSLATE[(*alpha & spermutation(plain ^ key) ^ *beta & suffer) as usize] as i64 }
            }).sum::<i64>());

            (key, ka_kount)
        }).collect::<Vec<_>>();
        selected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        selected.iter().take(100).for_each(|(&key, _)| {
            if let Some(count) = keys_candidates.get_mut(&key) {
                *count += 1;
            } else {
                keys_candidates.insert(key, 1);
            }
        });
    });

    let mut keys_selected: Vec<(&u16, &u16)> = keys_candidates.iter().collect::<Vec<(&u16, &u16)>>();
    keys_selected.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
    // println!("Sorted kandidatis: {keys_selected:?}");

    println!("Top 10 selected keys:");
    keys_selected.iter().take(10).for_each(|(key, kakaunt)| {
        println!("{key:x} : {kakaunt} times")
    });
}


