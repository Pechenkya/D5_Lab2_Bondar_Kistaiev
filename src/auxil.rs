use std::io::{Read, Write};
use rand::seq::SliceRandom;
use std::fs::File;
use std::io::{BufWriter, BufReader, BufRead};
use std::error::Error;


pub fn bytes_to_u16(pair: [u8; 2]) -> u16
{
    (u16::from(pair[1]) << 8) ^ u16::from(pair[0])
}

pub fn u16_to_bytes(value: u16) -> [u8; 2]
{
    value.to_le_bytes()
}

pub fn read_bytes_from_file(path: &str) -> Vec<u8>
{
    let mut file = std::fs::File::open(path).expect("Unable to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Unable to read file");

    buffer
}

pub fn write_bytes_to_file(path: &str, data: &[u8])
{
    let mut file = std::fs::File::create(path).expect("Unable to create file");
    file.write_all(data).expect("Unable to write data");
}

pub fn read_key(path: &str) -> [u16; 7] {
    let mut keys: [u16; 7] = [0; 7];
    let data = read_bytes_from_file(path);

    // Split into u16 pairs
    for i in 0..7 {
        keys[i] = bytes_to_u16(data[i * 2..i * 2 + 2].try_into().unwrap());
    }

    keys
} 

pub fn random_bytes_to_file_with_shifted(path: &str, path_shifted_1: &str, shift_1: u16, 
                                                     path_shifted_2: &str, shift_2: u16, 
                                                     path_shifted_3: &str, shift_3: u16, 
                                                     path_shifted_4: &str, shift_4: u16, size: usize, ) {
    let mut buffer = vec![0u8; 2 * size];

    let mut cnt: u16 = 0;
    let mut itr = 0;
    buffer.fill_with(|| {
        let [l, r] = u16_to_bytes(cnt);
        itr ^= 1;

        if itr == 0 {
            cnt += 1;
            l
        }
        else {
            r
        }
    });

    write_bytes_to_file(path, &buffer);

    let mut buffer_shift_1: Vec<u8> = Default::default();
    let mut buffer_shift_2: Vec<u8> = Default::default();
    let mut buffer_shift_3: Vec<u8> = Default::default();
    let mut buffer_shift_4: Vec<u8> = Default::default();
    for tuple in buffer.chunks_exact_mut(2) {
        let value = bytes_to_u16(tuple.try_into().unwrap());

        let [a, b] = u16_to_bytes(value ^ shift_1);
        buffer_shift_1.push(a);
        buffer_shift_1.push(b);
        
        let [a, b] = u16_to_bytes(value ^ shift_2);
        buffer_shift_2.push(a);
        buffer_shift_2.push(b);
        
        let [a, b] = u16_to_bytes(value ^ shift_3);
        buffer_shift_3.push(a);
        buffer_shift_3.push(b);
        
        let [a, b] = u16_to_bytes(value ^ shift_4);
        buffer_shift_4.push(a);
        buffer_shift_4.push(b);
    }
    write_bytes_to_file(path_shifted_1, &buffer_shift_1);
    write_bytes_to_file(path_shifted_2, &buffer_shift_2);
    write_bytes_to_file(path_shifted_3, &buffer_shift_3);
    write_bytes_to_file(path_shifted_4, &buffer_shift_4);
}

pub fn sample_random_bytes_from_file(path_to_plain: &str, path_to_cypher: &str, count: usize) -> Vec<(u16, u16)> {
    let plain_data = read_bytes_from_file(path_to_plain);
    let cypher_data = read_bytes_from_file(path_to_cypher);

    let mut rng = rand::rng();
    let mut samples: Vec<(u16, u16)> = Vec::new();
    let mut indices: Vec<usize> = (0..plain_data.len() / 2).collect();
    indices.shuffle(&mut rng);
    indices.truncate(count);

    for i in indices {
        let plain = bytes_to_u16(plain_data[i * 2..i * 2 + 2].try_into().unwrap());
        let cypher = bytes_to_u16(cypher_data[i * 2..i * 2 + 2].try_into().unwrap());

        samples.push((plain, cypher));
    }

    samples
}


// Save a 2D Vec<f32> to a CSV file
pub fn save_f32_2dvec_to_csv(data: &Vec<Vec<f32>>, path: &str) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    for row in data {
        let line = row.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(writer, "{line}")?;
    }
    Ok(())
}

// Load a 2D Vec<f32> from a CSV file
pub fn load_f32_2dvec_from_csv(path: &str) -> Result<Vec<Vec<f32>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut data = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let row = line.split(',')
            .map(|s| s.trim().parse::<f32>())
            .collect::<Result<Vec<_>, _>>()?;
        data.push(row);
    }
    Ok(data)
}