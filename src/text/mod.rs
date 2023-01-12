use std::{cmp::Reverse, ops::Deref};

use float_ord::FloatOrd;
use itertools::Itertools;
use plotlib::{page::Page, repr::BarChart, view::CategoricalView};

pub mod english;

#[derive(Debug, Clone)]
pub struct ByteMap([usize; 256]);

impl Default for ByteMap {
    fn default() -> Self {
        Self([0; 256])
    }
}

impl<S: AsRef<[u8]>> From<S> for ByteMap {
    fn from(value: S) -> Self {
        let mut s = Self::default();
        value.as_ref().iter().for_each(|&b| s.insert(b));
        s
    }
}

impl ByteMap {
    pub fn iter(&self) -> impl Iterator<Item = (u8, usize)> + '_ {
        (0..=255u8)
            .filter(|&idx| self.0[idx as usize] != 0)
            .map(move |idx| (idx, self.0[idx as usize]))
    }

    pub fn insert(&mut self, b: u8) {
        self.0[b as usize] += 1;
    }

    pub fn print_histogram(&self) {
        let mut view = CategoricalView::new();

        let charts = self
            .iter()
            .sorted_by_key(|&(_, n)| Reverse(n))
            .take(32)
            .map(|(b, n)| BarChart::new(n as f64).label(format!("{:?}", b as char)));
        for chart in charts {
            view = view.add(chart);
        }
        view = view.x_label("Char values");
        let plot = Page::single(&view);
        // plot.save("output.svg").unwrap();
        let plot = plot.to_text().unwrap();
        // assert!(plot.len() > 0);
        eprintln!("{plot}");
    }
}

pub fn count_spaces(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&b| *b == b' ').count()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip_eq(b)
        .map(|(a, b)| a ^ b)
        .map(|x| x.count_ones() as usize)
        .sum()
}

pub trait ScoreFunction {
    fn score(input: &[u8]) -> f64;
}

#[derive(Debug, Clone, Copy)]
pub struct CountSpaces;

impl ScoreFunction for CountSpaces {
    fn score(input: &[u8]) -> f64 {
        input.iter().filter(|&b| *b == b' ').count() as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    data: Vec<u8>,
}

impl<S: AsRef<[u8]>> From<S> for Encrypted {
    fn from(value: S) -> Self {
        Self {
            data: Vec::from(value.as_ref()),
        }
    }
}

impl Deref for Encrypted {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl Encrypted {
    pub fn single_xor_decrypt(&self, key: u8) -> Vec<u8> {
        self.data.iter().map(|b| b ^ key).collect()
    }

    pub fn find_single_xor_key<S: ScoreFunction>(&self) -> Option<u8> {
        (0..=255).max_by_key(|&key| FloatOrd(S::score(&self.single_xor_decrypt(key))))
    }

    pub fn repeating_key_decrypt(&self, key: &[u8]) -> Vec<u8> {
        self.data
            .iter()
            .zip(key.iter().cycle())
            .map(|(i, k)| i ^ k)
            .collect_vec()
    }

    pub fn probable_key_length(&self) -> Option<usize> {
        let input: &[u8] = self.data.as_ref();
        (2..=40_usize).min_by_key(|&length| {
            let distance: f64 = [
                &input[0..length],
                &input[length..length * 2],
                &input[length * 2..length * 3],
                &input[length * 3..length * 4],
            ]
            .iter()
            .tuple_combinations()
            .map(|(a, b)| hamming_distance(a, b))
            .sum::<usize>() as f64
                / (6.0 * length as f64);
            FloatOrd(distance)
        })
    }

    pub fn find_repeating_xor_key<S: ScoreFunction>(&self, length: usize) -> Option<Vec<u8>> {
        let data = BucketedData::bucket(&self.data, length);
        let key = data
            .blocks()
            .filter_map(|d| d.find_single_xor_key::<S>())
            .collect_vec();
        (key.len() == length).then_some(key)
    }
}

pub struct BucketedData {
    // keylength: usize,
    buckets: Vec<Vec<u8>>,
}

impl BucketedData {
    pub fn bucket<S: AsRef<[u8]>>(input: S, n: usize) -> Self {
        let mut buckets = vec![vec![]; n];
        input
            .as_ref()
            .iter()
            .enumerate()
            .for_each(|(i, &b)| buckets[i % n].push(b));
        Self {
            // keylength: n,
            buckets,
        }
    }

    pub fn blocks(&self) -> impl Iterator<Item = Encrypted> + '_ {
        self.buckets.iter().map(Encrypted::from)
    }
}

pub fn construct_histogram(input: &[u8]) -> ByteMap {
    let mut map = ByteMap::default();
    input.iter().for_each(|&b| map.insert(b));
    map
}

#[cfg(test)]
mod tests {
    use super::hamming_distance;

    #[test]
    fn wakka_wakka() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }
}
