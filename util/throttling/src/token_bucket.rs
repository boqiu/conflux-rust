// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::Mutex;
use std::{
    cmp::min,
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct TokenBucket {
    max_tokens: u64,    // maximum tokens allowed in bucket
    cur_tokens: u64,    // current tokens in bucket
    recharge_rate: u64, // recharge N tokens per second
    default_cost: u64,  // default tokens to acquire once
    last_update: Instant,

    // once acquire failed, record the next time to acquire tokens
    throttled: Option<Instant>,
}

impl TokenBucket {
    pub fn new(
        max_tokens: u64, cur_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        assert!(cur_tokens <= max_tokens);

        TokenBucket {
            max_tokens,
            cur_tokens,
            recharge_rate,
            default_cost,
            last_update: Instant::now(),
            throttled: None,
        }
    }

    pub fn full(
        max_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        Self::new(max_tokens, max_tokens, recharge_rate, default_cost)
    }

    pub fn empty(
        max_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        Self::new(max_tokens, 0, recharge_rate, default_cost)
    }

    fn refresh(&mut self) {
        let elapsed_secs = self.last_update.elapsed().as_secs();
        if elapsed_secs == 0 {
            return;
        }

        let recharged = self.recharge_rate * elapsed_secs;
        self.cur_tokens = min(self.max_tokens, self.cur_tokens + recharged);
        self.last_update += Duration::from_secs(elapsed_secs);
    }

    pub fn try_acquire(&mut self) -> Result<(), Duration> {
        self.try_acquire_cost(self.default_cost)
    }

    pub fn try_acquire_cost(&mut self, cost: u64) -> Result<(), Duration> {
        self.refresh();

        if cost <= self.cur_tokens {
            self.cur_tokens -= cost;
            self.throttled = None;
            return Ok(());
        }

        let recharge_secs = ((cost - self.cur_tokens) as f64
            / self.recharge_rate as f64)
            .ceil() as u64;

        let next_time = self.last_update + Duration::from_secs(recharge_secs);
        self.throttled = Some(next_time);

        let now = Instant::now();
        if next_time > now {
            Err(next_time - now)
        } else {
            Err(Duration::default())
        }
    }

    pub fn update_recharge_rate(&mut self, rate: u64) {
        self.refresh();

        self.recharge_rate = rate;
    }

    pub fn throttled(&self) -> Option<Instant> { self.throttled }
}

#[derive(Default)]
pub struct TokenBucketManager {
    // manage buckets by name
    buckets: HashMap<String, Arc<Mutex<TokenBucket>>>,
}

impl TokenBucketManager {
    pub fn register(&mut self, name: String, bucket: TokenBucket) {
        if self.buckets.contains_key(&name) {
            panic!("token bucket {:?} already registered", name);
        }

        self.buckets.insert(name, Arc::new(Mutex::new(bucket)));
    }

    pub fn get(&self, name: &String) -> Option<Arc<Mutex<TokenBucket>>> {
        self.buckets.get(name).cloned()
    }
}
