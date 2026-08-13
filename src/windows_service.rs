//! Native Windows service integration (cfg(windows)).
//!
//! `--install-service` / `--uninstall-service` register and remove the
//! `persea` service with the Service Control Manager (SCM). The service
//! runs as LocalSystem and keeps its data in `%ProgramData%\persea`
//! (database, recordings, certificates, config).
//!
//! When the process is started by the SCM, `dispatch()` hands control to
//! the service dispatcher, which runs the server on its own tokio runtime
//! and forwards SCM stop requests to the server's graceful shutdown path.
//! When started from a console, `dispatch()` fails with
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) and the caller runs in
//! the foreground instead.

use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
pub use windows_service::Error as ServiceError;

/// Service name registered with the SCM. `service_dispatcher::start` must
/// use exactly the name the service was created with.
pub const SERVICE_NAME: &str = "persea";

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: returned by
/// `service_dispatcher::start` when the process was NOT started by the SCM
/// (i.e. it was launched from a console). Not an error in that case — the
/// caller falls back to running in the foreground.
pub const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

/// Set by the service control handler when the SCM asks us to stop.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The server future handed to [`dispatch`]. The SCM calls the service main
/// through a bare extern fn, so the future travels through a static slot.
static SERVER_FUTURE: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>> = Mutex::new(None);

/// `%ProgramData%\persea` — the service data root.
pub fn program_data_dir() -> PathBuf {
    std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
        .join("persea")
}

/// Register the `persea` service with the SCM (LocalSystem, auto-start).
/// Idempotent: if the service already exists it is left untouched, so an
/// upgrade can reinstall over the same path without uninstalling first.
/// Run as Administrator.
pub fn install_service() -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    if manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        println!("Service '{}' is already installed", SERVICE_NAME);
        return Ok(());
    }

    let executable_path = std::env::current_exe().map_err(|e| {
        windows_service::Error::Winapi(std::io::Error::new(e.kind(), e.to_string()))
    })?;

    let service = manager.create_service(
        &ServiceInfo {
            name: SERVICE_NAME.to_string().into(),
            display_name: "persea — Guacamole-compatible web proxy".to_string().into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path,
            launch_arguments: Vec::new(),
            // LocalSystem (no account), data in %ProgramData%\persea.
            account_name: None,
            account_password: None,
            dependencies: Vec::new(),
        },
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
    )?;

    let _ = service.set_description(
        "persea Guacamole proxy. Data lives in %ProgramData%\\persea. \
         Manage with: persea.exe --uninstall-service",
    );

    println!(
        "Service '{}' installed (auto-start, LocalSystem)",
        SERVICE_NAME
    );
    println!("Start it now with: net start {}", SERVICE_NAME);
    Ok(())
}

/// Stop (if running) and delete the `persea` service. Run as Administrator.
pub fn uninstall_service() -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    if service.query_status()?.current_state == ServiceState::Running {
        println!("Requesting service '{}' stop...", SERVICE_NAME);
        let _ = service.stop();
        // Wait up to ~30s for the service to leave the Running state.
        for _ in 0..120 {
            if service.query_status()?.current_state != ServiceState::Running {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    service.delete()?;
    println!("Service '{}' uninstalled", SERVICE_NAME);
    Ok(())
}

/// SCM control handler: stop/shutdown flip the flag the server's shutdown
/// path polls; everything else is answered with NotImplemented.
fn control_handler(event: ServiceControl) -> ServiceControlHandlerResult {
    match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

define_windows_service!(ffi_service_main, service_main);

/// Service main: runs the server future on a fresh tokio runtime and keeps
/// the SCM informed of the Running/Stopped state. Runs on a dispatcher
/// thread, never on the main thread.
fn service_main(_arguments: Vec<OsString>) {
    let server = match SERVER_FUTURE.lock().unwrap().take() {
        Some(s) => s,
        None => {
            eprintln!("FATAL: service main invoked without a server future");
            return;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("FATAL: failed to create tokio runtime: {}", e);
            return;
        }
    };

    let handle = match service_control_handler::register(SERVICE_NAME, control_handler) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("FATAL: failed to register service control handler: {}", e);
            return;
        }
    };

    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: windows_service::service::ServiceControlAccept::STOP
            | windows_service::service::ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    if let Err(e) = handle.set_service_status(running) {
        eprintln!("FATAL: failed to report Running state: {}", e);
        return;
    }

    tracing::info!("persea service is running (LocalSystem, data in %ProgramData%\\persea)");

    rt.block_on(async move { server.await });

    let stopped = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: windows_service::service::ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let _ = handle.set_service_status(stopped);
    tracing::info!("persea service stopped");
}

/// Runs `server` under the SCM. Blocks the calling thread for the lifetime
/// of the service; returns `Ok(())` when the service stops, or an error
/// with `raw_os_error() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when
/// the process was not started by the SCM (the caller should then run in
/// the foreground).
pub fn dispatch(
    server: impl Future<Output = ()> + Send + 'static,
) -> Result<(), windows_service::Error> {
    {
        let mut slot = SERVER_FUTURE.lock().unwrap();
        if slot.is_some() {
            return Err(windows_service::Error::Winapi(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "service main already dispatched",
            )));
        }
        *slot = Some(Pin::from(Box::new(server)));
    }
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// Completes when the SCM has asked the service to stop. Selected against
/// ctrl-c in the server's shutdown futures (main.rs).
pub async fn wait_for_stop() {
    loop {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
