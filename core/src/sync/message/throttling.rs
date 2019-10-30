// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    sync::{
        message::{Context, Handleable},
        Error, ErrorKind,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::time::{Duration, Instant};

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct Throttled {
    pub msg_id: MsgId,
    pub wait_time_nanos: u64,
    // resend request to another peer if throttled
    pub request_id: Option<RequestId>,
}

impl Handleable for Throttled {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        if let Some(peer) = ctx.manager.syn.peers.read().get(&ctx.peer) {
            peer.write().throttled_msgs.insert(
                self.msg_id,
                Instant::now() + Duration::from_nanos(self.wait_time_nanos),
            );
        }

        if let Some(request_id) = self.request_id {
            let request = ctx.match_request(request_id)?;
            ctx.manager
                .request_manager
                .send_request_again(ctx.io, &request);
        }

        Ok(())
    }
}

pub trait ThrottleMessage {
    fn throttle(self, ctx: &Context) -> Result<Self, Error>
    where Self: Sized;
}

impl<T: Message + Sized> ThrottleMessage for T {
    fn throttle(self, ctx: &Context) -> Result<Self, Error> {
        let peer = match ctx.manager.syn.peers.read().get(&ctx.peer) {
            Some(peer) => peer.clone(),
            None => return Ok(self),
        };

        let bucket_name = self.msg_name().to_string();
        let bucket = match peer.read().throttling.get(&bucket_name) {
            Some(bucket) => bucket,
            None => return Ok(self),
        };

        let mut bucket = bucket.lock();

        // already throttled
        if let Some(until) = bucket.throttled() {
            if Instant::now() < until {
                return Err(ErrorKind::AlreadyThrottled(self.msg_name()).into());
            }
        }

        // throttle with default cost
        if let Err(wait_time) = bucket.try_acquire() {
            let throttled = Throttled {
                msg_id: self.msg_id(),
                wait_time_nanos: wait_time.as_nanos() as u64,
                request_id: None,
            };

            return Err(ErrorKind::Throttled(self.msg_name(), throttled).into());
        }

        Ok(self)
    }
}

// todo (boqiu): merge the HasRequestId into Message trait
pub trait ThrottleRequest {
    fn throttle_request(self, ctx: &Context) -> Result<Self, Error>
    where Self: Sized;
}

impl<T: Message + HasRequestId + Sized> ThrottleRequest for T {
    fn throttle_request(self, ctx: &Context) -> Result<Self, Error> {
        let request_id = self.request_id();

        let (name, mut throttled) = match self.throttle(ctx) {
            Ok(msg) => return Ok(msg),
            Err(Error(ErrorKind::Throttled(name, throttled), _)) => {
                (name, throttled)
            }
            Err(e) => return Err(e),
        };

        // fill the request id
        throttled.request_id = Some(request_id);

        Err(ErrorKind::Throttled(name, throttled).into())
    }
}
