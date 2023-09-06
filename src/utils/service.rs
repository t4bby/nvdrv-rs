#![allow(unused_imports)]

use std::ffi::{OsString};
use std::{mem, ptr};
use std::path::PathBuf;
use widestring::{WideCString, WideString};
use windows_sys::Win32;
use windows_sys::Win32::System::Services;
use windows_sys::Win32::Security;
use std::ffi::OsStr;
use std::io::Error;
use bitflags::Flags;

/// Reference:
/// https://github.com/mullvad/windows-service-rs/blob/main/src/sc_handle.rs#L4
pub struct ScHandle(Security::SC_HANDLE);

impl ScHandle {
    pub unsafe fn new(handle: Security::SC_HANDLE) -> Self {
        ScHandle(handle)
    }

    pub fn get_handle(&self) -> Security::SC_HANDLE {
        self.0
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {Services::CloseServiceHandle(self.0)};
    }
}


bitflags::bitflags! {
    /// Flags describing access permissions for [`ServiceManager`].
    #[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone, Hash)]
    pub struct ServiceManagerAccess: u32 {
        /// Can connect to service control manager.
        const CONNECT = Services::SC_MANAGER_CONNECT;

        /// Can create services.
        const CREATE_SERVICE = Services::SC_MANAGER_CREATE_SERVICE;

        /// Can enumerate services or receive notifications.
        const ENUMERATE_SERVICE = Services::SC_MANAGER_ENUMERATE_SERVICE;
    }
}
/// Service manager.
pub struct ServiceManager {
    manager_handle: ScHandle,
}

impl ServiceManager {
    pub(crate) fn new(request_access: ServiceManagerAccess) -> Result<Self, Error> {
        let handle = unsafe {
            Services::OpenSCManagerW(
                ptr::null(),
                ptr::null(),
                request_access.bits(),
            )
        };

        if handle == 0 {
            return Err(Error::last_os_error());
        } else {
            Ok(ServiceManager {
                manager_handle: unsafe { ScHandle::new(handle) },
            })
        }
    }

    pub fn create_service(&self, service_info: &ServiceInfo,
                          service_access: ServiceAccess) ->  Result<Service, Error>  {
        let raw_info = RawServiceInfo::new(service_info)?;

        let service_handle = unsafe {
            Services::CreateServiceW(
                self.manager_handle.get_handle(),
                raw_info.name.as_ptr(),
                raw_info.display_name.as_ptr(),
                service_access.bits(),
                raw_info.service_type,
                raw_info.start_type,
                raw_info.error_control,
                raw_info.launch_command.as_ptr(),
                ptr::null(),     // load ordering group
                ptr::null_mut(), // tag id within the load ordering group
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };

        if service_handle == 0 {
            return Err(Error::last_os_error());
        } else {
            Ok(Service::new(unsafe { ScHandle::new(service_handle) }))
        }
    }
    pub fn open_service(
        &self,
        name: impl AsRef<OsStr>,
        request_access: ServiceAccess,
    ) -> Result<Service, Error> {
        let service_name = WideCString::from_os_str(name)
            .map_err(|_| Error::last_os_error())?;

        let service_handle = unsafe {
            Services::OpenServiceW(
                self.manager_handle.get_handle(),
                service_name.as_ptr(),
                request_access.bits(),
            )
        };

        if service_handle == 0 {
            return Err(Error::last_os_error())
        } else {
            Ok(Service::new(unsafe { ScHandle::new(service_handle) }))
        }
    }

}

/// Enum describing the start options for windows services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ServiceStartType {
    /// Service is enabled, can be started manually
    OnDemand = Services::SERVICE_DEMAND_START,
}


bitflags::bitflags! {
    /// Flags describing the access permissions when working with services
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct ServiceAccess: u32 {
        /// Can query the service status
        const QUERY_STATUS = Services::SERVICE_QUERY_STATUS;

        /// Can start the service
        const START = Services::SERVICE_START;

        /// Can stop the service
        const STOP = Services::SERVICE_STOP;

        /// Can pause or continue the service execution
        const PAUSE_CONTINUE = Services::SERVICE_PAUSE_CONTINUE;

        /// Can ask the service to report its status
        const INTERROGATE = Services::SERVICE_INTERROGATE;

        /// Can delete the service
        const DELETE = Win32::Storage::FileSystem::DELETE;

        /// Can query the services configuration
        const QUERY_CONFIG = Services::SERVICE_QUERY_CONFIG;

        /// Can change the services configuration
        const CHANGE_CONFIG = Services::SERVICE_CHANGE_CONFIG;
    }
}

bitflags::bitflags! {
    /// Enum describing the types of Windows services.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct ServiceType: u32 {
        /// File system driver service.
        const FILE_SYSTEM_DRIVER = Services::SERVICE_FILE_SYSTEM_DRIVER;

        /// Driver service.
        const KERNEL_DRIVER = Services::SERVICE_KERNEL_DRIVER;
    }
}

/// A struct that describes the service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceInfo {

    /// Service name
    pub name: OsString,

    /// User-friendly service name
    pub display_name: OsString,

    /// The service type
    pub service_type: ServiceType,

    /// The service startup options
    pub start_type: ServiceStartType,

    /// Path to the service binary
    pub executable_path: PathBuf,
}

/// Same as `ServiceInfo` but with fields that are compatible with the Windows API.
pub(crate) struct RawServiceInfo {
    /// Service name
    pub name: WideCString,

    /// User-friendly service name
    pub display_name: WideCString,

    /// The service type
    pub service_type: u32,

    /// The service startup options
    pub start_type: u32,

    /// The severity of the error, and action taken, if this service fails to start.
    pub error_control: u32,

    /// Path to the service binary with arguments appended
    pub launch_command: WideCString,

}


impl RawServiceInfo {
    pub fn new(service_info: &ServiceInfo) -> Result<Self, Error> {
        let service_name = WideCString::from_os_str(&service_info.name)
            .map_err(|_| Error::last_os_error())?;
        let display_name = WideCString::from_os_str(&service_info.display_name)
            .map_err(|_| Error::last_os_error())?;

        // escape executable path and arguments and combine them into a single command
        let mut launch_command_buffer = WideString::new();
        if service_info
            .service_type
            .intersects(ServiceType::KERNEL_DRIVER | ServiceType::FILE_SYSTEM_DRIVER)
        {
            // also the path must not be quoted even if it contains spaces
            let executable_path = WideCString::from_os_str(&service_info.executable_path)
                .map_err(|_| Error::last_os_error())?;
            launch_command_buffer.push(executable_path.to_ustring());
        }

        // Safety: We are sure launch_command_buffer does not contain nulls
        let launch_command = unsafe { WideCString::from_ustr_unchecked(launch_command_buffer) };

        Ok(Self {
            name: service_name,
            display_name,
            service_type: service_info.service_type.bits(),
            start_type: service_info.start_type as u32,
            error_control: 0,
            launch_command,
        })
    }
}

/// Service Handler
pub struct Service {
    handler: ScHandle
}

impl Service {

    pub fn new(handler: ScHandle) -> Self {
        Service { handler }
    }

    /// Start Service
    /// sc start service
    pub unsafe fn start_service(&self) -> Result<(), Error> {
        let success = unsafe {
            Services::StartServiceA(
                self.handler.get_handle(),
            0,
            ptr::null())
        };

        if success == 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }


    pub fn delete_service(&self) -> Result<(), Error>{
        let success = unsafe { Services::DeleteService(self.handler.get_handle()) };
        if success == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Stop the Service
    /// sc stop service
    pub fn stop_service(&self) -> Result<(), Error> {
        let mut raw_status = unsafe { mem::zeroed::<Services::SERVICE_STATUS>() };
        let success = unsafe {
            Services::ControlService(
                self.handler.get_handle(),
                Services::SERVICE_CONTROL_STOP,
                &mut raw_status,
            )
        };

        if success == 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }
}