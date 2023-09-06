use std::ffi::OsString;
use std::{fs, env};

use std::io::Error;

use crate::utils::service::{Service, ServiceAccess, ServiceInfo, ServiceManager, ServiceManagerAccess, ServiceStartType, ServiceState, ServiceType};

mod raw_driver;
pub mod service;

pub struct DriverService {
    manager: ServiceManager,
    pub service_info: ServiceInfo,
}

impl DriverService {
    pub fn new() -> Self {
        let service_name: String = String::from("t4bby");
        let service_file_name = service_name.clone() + ".sys";

        DriverService {
            manager: ServiceManager::new(ServiceManagerAccess::CREATE_SERVICE).unwrap(),
            service_info: ServiceInfo {
                name: OsString::from(&service_name),
                display_name: OsString::from(&service_name),
                service_type: ServiceType::KERNEL_DRIVER,
                start_type: ServiceStartType::OnDemand,
                executable_path: env::temp_dir().join(service_file_name),
            },
        }
    }

    pub fn create_driver_file(&self) -> Result<(), Error> {
        fs::write(&self.service_info.executable_path,
                  raw_driver::RAW_DRIVER)
    }

    pub fn start_driver(&self) -> Result<(), Error>{

        let service: Service = self.manager.create_service(
            &self.service_info,
            ServiceAccess::START).unwrap();

        unsafe { service.start_service() }
    }

    pub fn stop_driver(&self) -> Result<(), Error> {
        let service = self.manager.open_service(
            &self.service_info.name,
            ServiceAccess::STOP)?;

        service.stop_service()
    }

    pub fn delete_driver(&self) -> Result<(), Error> {
        let service = self.manager.open_service(
            &self.service_info.name,
            ServiceAccess::DELETE)?;

        service.delete_service()
    }

    pub fn status_driver(&self) -> Result<ServiceState, Error> {
        let service = self.manager.open_service(
            &self.service_info.name,
            ServiceAccess::QUERY_STATUS)?;

        service.query_status()
    }

}