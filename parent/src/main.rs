use tonic::transport::Server;
use tracing_subscriber::{prelude::*, EnvFilter};

use utexo_bridge_parent::config::Config;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let swap_configured = utexo_bridge_parent::swap_persistence::configured();
    tracing_subscriber::registry()
        // SDK trace events may contain signed requests. Broker diagnostics use
        // fixed categories and must stay safe even when RUST_LOG enables debug.
        .with(
            tracing_subscriber::fmt::layer()
                .with_filter(EnvFilter::from_default_env())
                .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
                    !swap_configured
                        || !["aws_", "hyper", "h2", "rustls"]
                            .iter()
                            .any(|prefix| metadata.target().starts_with(prefix))
                })),
        )
        .init();

    let cfg = Config::from_env();
    let broker = utexo_bridge_parent::swap_persistence::start(&cfg).await?;

    let target = if cfg.use_vsock {
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                cid = cfg.enclave_vsock_cid,
                port = cfg.enclave_vsock_port,
                "enclave target: vsock"
            );
            EnclaveTarget::Vsock {
                cid: cfg.enclave_vsock_cid,
                port: cfg.enclave_vsock_port,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err("vsock is only supported on Linux".into());
        }
    } else {
        tracing::info!(addr = %cfg.enclave_addr, "enclave target: TCP");
        EnclaveTarget::Tcp(cfg.enclave_addr)
    };

    tracing::info!(evm_network_ids = ?cfg.evm_network_ids, "EVM network IDs for TRANSACTION routing");
    let service = ParentAdapterService::new(target, cfg.evm_network_ids);
    let listen_addr = format!("{}:{}", cfg.grpc_host, cfg.grpc_port).parse()?;

    tracing::info!(%listen_addr, "starting gRPC server");

    let server = Server::builder()
        .add_service(ParentServiceServer::new(service))
        .serve(listen_addr);
    if let Some(broker) = broker {
        tokio::select! {
            result = server => result?,
            _ = broker => return Err("swap persistence listener stopped".into()),
        }
    } else {
        server.await?;
    }

    Ok(())
}
