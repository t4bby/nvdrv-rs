use std::ffi::OsString;
use std::{env, fs};
use std::io::Error;
use rand::{distributions::Alphanumeric, Rng};

use crate::utils::service::{Service, ServiceAccess, ServiceInfo, ServiceManager, ServiceManagerAccess, ServiceStartType, ServiceType};

mod raw_driver;
mod service;

pub struct DriverService {
    manager: ServiceManager,
    service_info: ServiceInfo,
}

impl DriverService {
    pub fn new() -> Self {
        let service_name: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

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
        let service: Service = self.manager.open_service(
            &self.service_info.name,
            ServiceAccess::STOP | ServiceAccess::DELETE).unwrap();

        let stop_status = service.stop_service();
        match stop_status {
            Ok(_) => {
                service.delete_service().unwrap();
                fs::remove_file(&self.service_info.executable_path)
            },
            Err(i) => Err(i)
        }
    }

}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;
    use super::*;

    #[test]
    fn test_start() {
        let drv = DriverService::new();
        drv.create_driver_file().unwrap();
        drv.start_driver().unwrap();
        thread::sleep(Duration::from_secs(5));
    }

    #[test]
    fn test_stop() {
        thread::sleep(Duration::from_secs(5));
        let drv = DriverService::new();
        drv.stop_driver().unwrap();
    }
}