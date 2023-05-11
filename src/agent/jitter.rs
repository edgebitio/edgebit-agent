use std::time::Duration;

use rand::rngs::ThreadRng;
use rand::distributions::{Distribution, Uniform};

pub struct JitteredDuration {
    rng: ThreadRng,
    dist: Uniform<i64>,
}

impl JitteredDuration {
    pub fn new(magnitude: Duration) -> Self {
        let mag = magnitude.as_secs() as i64;

        Self{
            rng: rand::thread_rng(),
            dist: Uniform::from(-mag..mag),
        }
    }

    pub fn add(&mut self, base: Duration) -> Duration {
        let jitter = self.dist.sample(&mut self.rng);
        if jitter < 0 {
            base - Duration::from_secs(-jitter as u64)
        } else {
            base + Duration::from_secs(jitter as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_jittered_duration() {
        let mut jitter = JitteredDuration::new(Duration::from_secs(10));

        // make sure not all are right at 60
        let mut non_center = 0;
        let center = Duration::from_secs(60);
        
        for _ in 0..1000 {
            let s = jitter.add(center);
            assert!(s >= Duration::from_secs(50));
            assert!(s <= Duration::from_secs(70));

            if s != center {
                non_center += 1;
            }
        }

        assert!(non_center > 0);
    }
}