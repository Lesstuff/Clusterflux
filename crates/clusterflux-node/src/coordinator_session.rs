#[cfg(test)]
use clusterflux_client::endpoint_identity;
use clusterflux_client::ProtocolSession;
use clusterflux_client::{ClusterfluxClient, ControlTransport};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use std::time::Duration;

pub(crate) struct CoordinatorSession {
    inner: ProtocolSession,
}

#[derive(Clone)]
pub(crate) struct AsyncCoordinatorSession {
    inner: ClusterfluxClient,
}

impl AsyncCoordinatorSession {
    pub(crate) fn connect_with_timeouts(
        addr: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, String> {
        let transport = ControlTransport::with_timeouts(addr, connect_timeout, io_timeout)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            inner: ClusterfluxClient::with_transport(transport),
        })
    }

    pub(crate) async fn request(
        &self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, String> {
        self.inner
            .send_coordinator_request(request)
            .await
            .map_err(|error| error.to_string())
    }
}

impl CoordinatorSession {
    pub(crate) fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: ProtocolSession::connect(addr, "node")?,
        })
    }

    pub(crate) fn connect_with_timeouts(
        addr: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: ProtocolSession::connect_with_timeouts(
                addr,
                "node",
                connect_timeout,
                io_timeout,
            )?,
        })
    }

    pub(crate) fn request(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, Box<dyn std::error::Error>> {
        Ok(self.inner.request(&request)?)
    }

    pub(crate) fn requests(&self) -> usize {
        self.inner.requests() as usize
    }
}

#[cfg(test)]
pub(crate) fn control_endpoint_identity(
    endpoint: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(endpoint_identity(endpoint)?)
}
