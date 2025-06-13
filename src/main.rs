#![allow(dead_code, non_snake_case)]
mod auxil;
use std::collections::HashMap;
use rayon::prelude::*;

use crate::auxil::*;

// Substitution for Variant 2
const S_BLOCK: [u16; 16] = [0x8, 0x0, 0xC, 0x4, 0x9, 0x6, 0x7, 0xB, 0x2, 0x3, 0x1, 0xF, 0x5, 0xE, 0xA, 0xD];

// Inverted substitution
const S_INV:   [u16; 16] = [0x1, 0xA, 0x8, 0x9, 0x3, 0xC, 0x5, 0x6, 0x0, 0x4, 0xE, 0x7, 0x2, 0xF, 0xD, 0xB];

// Precomputed permutation table (Permytation will be the same for inverse)
static mut PERMUTATION_TABLE: [u16; 65536] = [0u16; 65536];
unsafe fn precalc_perm() {
    for x in 0u16..=65535u16 {
        for i in 0..=3 {
            PERMUTATION_TABLE[usize::from(x)] ^= ((((x >> (i * 4)) & 0b0001)) ^ 
                                                 ((((x >> (i * 4)) & 0b0010)) << 3) ^
                                                 ((((x >> (i * 4)) & 0b0100)) << 6) ^ 
                                                 ((((x >> (i * 4)) & 0b1000)) << 9)) << i;
        }
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
fn generate_dps_table() -> Vec<HashMap<u16, f32>> {
    let dps_table: Vec<HashMap<u16, f32>> = (0..=65535).into_par_iter()
        .map(|alph| {
            let mut mp = HashMap::<u16, f32>::new();
            for x in 0..=65535 {
                let beta = spermutation(x) ^ spermutation(x ^ alph);

                if let Some(c) = mp.get_mut(&beta) {
                    *c += 1.;
                } else {
                    mp.insert(beta, 1.);
                }
            }

            mp.iter_mut().for_each(|(_, v)| {
                *v /= 65536.0;
            });

            mp
        }).collect();

    dps_table
}

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
    }

    /* Branch and bound for all alphas with requirement of prob >= 0.0004 */ 
    let dps_table = generate_dps_table();
    let prob_bound = 0.0004f32;

    (0..=65535).into_par_iter().map(|alpha| {
        let res = branch_and_bound(alpha, 5, prob_bound, &dps_table)
            .into_iter().filter(|(beta, _)| (beta & 0xF000 != 0) &&
                                            (beta & 0x0F00 != 0) &&
                                            (beta & 0x00F0 != 0) &&
                                            (beta & 0x000F != 0)).collect::<HashMap<u16, f32>>();
        (alpha, res)
    }).filter(|(_, map)| !map.is_empty()).for_each(|(alpha, map)| println!("{alpha}: {map:?}"));
    
    /* Result of calculation:
        2: {34952: 0.0007625818}
        3: {34952: 0.000984937}
        4: {34952: 0.00044059753}
        6: {34952: 0.0006748438}
        9: {34952: 0.000579834}
        11: {34952: 0.00046348572}
        12: {34952: 0.00044631958}
        13: {34952: 0.00046157837}
        14: {34952: 0.0004210472}
        15: {34952: 0.00074768066}
        32: {4369: 0.0004528761, 8738: 0.00050997734}
        48: {4369: 0.0005618483, 8738: 0.00065054}
        96: {8738: 0.0004298687}
        144: {8738: 0.00045585632}
        240: {8738: 0.0005264282, 4369: 0.00046157837}
        768: {34952: 0.00048935413, 17476: 0.00050520897}
     */
    

    /* Get full probability for selected alpha-beta pair */ 
    let alpha = [3, 48, 240, 768];
    let beta = [32904, 8738, 4369, 17476];

    // for (a, b) in alpha.iter().zip(beta.iter()) {
    //     let ab_prob = (0..=65535).into_par_iter().map(|k| {
    //         (0..=65535).into_par_iter().map(|mut x| {
    //             let mut x_shtrix = x ^ a;
    //             for _ in 0..=4 {
    //                 x = heys_round(x, k);
    //                 x_shtrix = heys_round(x_shtrix, k);
    //             }  

    //             (x == (x_shtrix ^ b)) as u32
    //         }).sum::<u32>()
    //     }).sum::<u32>() as f32 / (65536.0 * 65536.0);

    //     println!("Alpha: {a}, Beta: {b}, Probability: {ab_prob}");
    // }

    /* Selected results results (with statistic values):
        Alpha: 3,   Beta: 32904, Probability: 0.0019441145  (0.000984937)   -> N = 15000 & ka_kount = 15
        Alpha: 48,  Beta: 8738,  Probability: 0.0007340037  (0.00065054)    -> N = 15000 & ka_kount = 4
        Alpha: 240, Beta: 4369,  Probability: 0.00050009927 (0.00046157837) -> N = 15000 & ka_kount = 4
        Alpha: 768, Beta: 17476, Probability: 0.0006229584  (0.00050520897) -> N = 15000 & ka_kount = 4
     */ 

    
    /* Generate all possible block inpust & themself with selected shifts */
    // random_bytes_to_file_with_shifted("test_data/open.txt", "test_data/open_shifted_1.txt", alpha[1],
    //                                                         "test_data/open_shifted_2.txt", alpha[2],
    //                                                         "test_data/open_shifted_3.txt", alpha[3],
    //                                                         "test_data/open_shifted_4.txt", alpha[4], 65536);
         
    // /* OUT THE PROGRAM: Then we encrypt the files with variant key */
    // for i

    // /* Generate samples of precalculated sizes (statistic values) */
    let N = 15000;
    let ka_kount_krit = [15, 4, 3, 3];

    
    let samples = sample_random_bytes_from_file("test_data/open.txt", "test_data/cypher.txt",
                                                "test_data/open_shifted_1.txt", "test_data/cypher_shifted_1.txt",
                                                "test_data/open_shifted_2.txt", "test_data/cypher_shifted_2.txt",
                                                "test_data/open_shifted_3.txt", "test_data/cypher_shifted_3.txt",
                                                "test_data/open_shifted_4.txt", "test_data/cypher_shifted_4.txt", N);
    
    let mut keys = (0..=65535).map(|k| k as u16).collect::<Vec<_>>();
    for i in 0..4 {
        println!("Iteration {} ({}, {}):", i + 1, alpha[i], beta[i]);                 
        keys = keys.into_iter().map(|k| {
            let ka_kount = samples.iter().map(|[_, cypher]| { 
                (beta[i] == unspermutation(cypher[0] ^ k) ^ unspermutation(cypher[i + 1] ^ k)) as u16
            }).sum::<u16>();
            
            if ka_kount >= ka_kount_krit[i] {
                println!("\tKey: {k:04x}, Count: {ka_kount}");
                k
            }
            else {
                0
            }
        }).filter(|k| *k != 0).collect::<Vec<_>>();
        println!("Filtered keys: {keys:04x?}");
    }

    println!("Selected keys: {keys:04x?}");
    /* Result:
        Iteration 1 (3, 32904):
                Key: 01ba, Count: 31
                Key: 01be, Count: 31
                Key: 01fa, Count: 31
                Key: 01fe, Count: 31
                Key: 05ba, Count: 31
                Key: 05be, Count: 31
                Key: 05fa, Count: 31
                Key: 05fe, Count: 31
                Key: 41ba, Count: 31
                Key: 41be, Count: 31
                Key: 41fa, Count: 31
                Key: 41fe, Count: 31
                Key: 45ba, Count: 31
                Key: 45be, Count: 31
                Key: 45fa, Count: 31
                Key: 45fe, Count: 31
        Filtered keys: [01ba, 01be, 01fa, 01fe, 05ba, 05be, 05fa, 05fe, 41ba, 41be, 41fa, 41fe, 45ba, 45be, 45fa, 45fe]
        Iteration 2 (48, 8738):
                Key: 01be, Count: 14
                Key: 45ba, Count: 4
                Key: 45be, Count: 7
                Key: 45fe, Count: 6
        Filtered keys: [01be, 45ba, 45be, 45fe]
        Iteration 3 (240, 4369):
                Key: 01be, Count: 9
                Key: 45be, Count: 3
        Filtered keys: [01be, 45be]
        Iteration 4 (768, 17476):
                Key: 01be, Count: 17
        Filtered keys: [01be]
        Selected keys: [01be]
     */
}


fn mul(x: u32, y: u32) -> u32 {
    let mut x = x & y;
    let mut s = 0;
    while x != 0 {
        s ^= x & 1;
        x >>= 1;
    }

    s
}

fn LP(a: u32, b: u32, s: &[u32]) {
    for x in 0..=0xf {
        let bf = mul(b, s[x]);
        let ax = mul(a, x as u32);
        let s = s[x];
        println!("{a}*{x} xor {b}*{s} = {ax} xor {bf} = {}", ax ^ bf);
    }
}
