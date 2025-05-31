/// Function cluster codes for MIFARE Application Directory.
///
/// Based on:
/// - [NXP Application Note AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionCluster {
    MiscellaneousApplications01 = 0x01,
    MiscellaneousApplications02 = 0x02,
    MiscellaneousApplications03 = 0x03,
    MiscellaneousApplications04 = 0x04,
    MiscellaneousApplications05 = 0x05,
    MiscellaneousApplications06 = 0x06,
    MiscellaneousApplications07 = 0x07,
    Airlines = 0x08,
    FerryTraffic = 0x09,
    RailwayServices = 0x10,
    MiscellaneousApplications11 = 0x11,
    Transport = 0x12,
    SecuritySolutions = 0x14,
    CityTraffic = 0x18,
    CzechRailways = 0x19,
    BusServices = 0x20,
    MultiModalTransit = 0x21,
    Taxi = 0x28,
    RoadToll = 0x30,
    GenericTransport = 0x31,
    CompanyServices = 0x38,
    CityCardServices = 0x40,
    AccessControlSecurity47 = 0x47,
    AccessControlSecurity48 = 0x48,
    Vigik = 0x49,
    MinistryOfDefenceNl = 0x4A,
    BoschTelecomDe = 0x4B,
    EuInstitutions = 0x4C,
    SkiTicketing = 0x50,
    AccessControlSecurity51 = 0x51,
    AccessControlSecurity52 = 0x52,
    AccessControlSecurity53 = 0x53,
    AccessControlSecurity54 = 0x54,
    SoaaStandardOfflineAccess = 0x55,
    AcademicServices = 0x58,
    Food = 0x60,
    NonFoodTrade = 0x68,
    Hotel = 0x70,
    Loyalty = 0x71,
    AirportServices = 0x75,
    CarRental = 0x78,
    DutchGovernment = 0x79,
    AdministrationServices = 0x80,
    ElectronicPurse = 0x88,
    Television = 0x90,
    CruiseShip = 0x91,
    Iopta = 0x95,
    Metering = 0x97,
    Telephone = 0x98,
    HealthServices = 0xA0,
    Warehouse = 0xA8,
    ElectronicTrade = 0xB0,
    Banking = 0xB8,
    EntertainmentSports = 0xC0,
    CarParking = 0xC8,
    FleetManagement = 0xC9,
    FuelGasoline = 0xD0,
    InfoServices = 0xD8,
    Press = 0xE0,
    NfcForum = 0xE1,
    Computer = 0xE8,
    Mail = 0xF0,
    MiscellaneousApplicationsF8 = 0xF8,
    MiscellaneousApplicationsF9 = 0xF9,
    MiscellaneousApplicationsFA = 0xFA,
    MiscellaneousApplicationsFB = 0xFB,
    MiscellaneousApplicationsFC = 0xFC,
    MiscellaneousApplicationsFD = 0xFD,
    MiscellaneousApplicationsFE = 0xFE,
    MiscellaneousApplicationsFF = 0xFF,
}

impl TryFrom<u8> for FunctionCluster {
    type Error = MadAidError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FunctionCluster::MiscellaneousApplications01),
            0x02 => Ok(FunctionCluster::MiscellaneousApplications02),
            0x03 => Ok(FunctionCluster::MiscellaneousApplications03),
            0x04 => Ok(FunctionCluster::MiscellaneousApplications04),
            0x05 => Ok(FunctionCluster::MiscellaneousApplications05),
            0x06 => Ok(FunctionCluster::MiscellaneousApplications06),
            0x07 => Ok(FunctionCluster::MiscellaneousApplications07),
            0x08 => Ok(FunctionCluster::Airlines),
            0x09 => Ok(FunctionCluster::FerryTraffic),
            0x10 => Ok(FunctionCluster::RailwayServices),
            0x11 => Ok(FunctionCluster::MiscellaneousApplications11),
            0x12 => Ok(FunctionCluster::Transport),
            0x14 => Ok(FunctionCluster::SecuritySolutions),
            0x18 => Ok(FunctionCluster::CityTraffic),
            0x19 => Ok(FunctionCluster::CzechRailways),
            0x20 => Ok(FunctionCluster::BusServices),
            0x21 => Ok(FunctionCluster::MultiModalTransit),
            0x28 => Ok(FunctionCluster::Taxi),
            0x30 => Ok(FunctionCluster::RoadToll),
            0x31 => Ok(FunctionCluster::GenericTransport),
            0x38 => Ok(FunctionCluster::CompanyServices),
            0x40 => Ok(FunctionCluster::CityCardServices),
            0x47 => Ok(FunctionCluster::AccessControlSecurity47),
            0x48 => Ok(FunctionCluster::AccessControlSecurity48),
            0x49 => Ok(FunctionCluster::Vigik),
            0x4A => Ok(FunctionCluster::MinistryOfDefenceNl),
            0x4B => Ok(FunctionCluster::BoschTelecomDe),
            0x4C => Ok(FunctionCluster::EuInstitutions),
            0x50 => Ok(FunctionCluster::SkiTicketing),
            0x51 => Ok(FunctionCluster::AccessControlSecurity51),
            0x52 => Ok(FunctionCluster::AccessControlSecurity52),
            0x53 => Ok(FunctionCluster::AccessControlSecurity53),
            0x54 => Ok(FunctionCluster::AccessControlSecurity54),
            0x55 => Ok(FunctionCluster::SoaaStandardOfflineAccess),
            0x58 => Ok(FunctionCluster::AcademicServices),
            0x60 => Ok(FunctionCluster::Food),
            0x68 => Ok(FunctionCluster::NonFoodTrade),
            0x70 => Ok(FunctionCluster::Hotel),
            0x71 => Ok(FunctionCluster::Loyalty),
            0x75 => Ok(FunctionCluster::AirportServices),
            0x78 => Ok(FunctionCluster::CarRental),
            0x79 => Ok(FunctionCluster::DutchGovernment),
            0x80 => Ok(FunctionCluster::AdministrationServices),
            0x88 => Ok(FunctionCluster::ElectronicPurse),
            0x90 => Ok(FunctionCluster::Television),
            0x91 => Ok(FunctionCluster::CruiseShip),
            0x95 => Ok(FunctionCluster::Iopta),
            0x97 => Ok(FunctionCluster::Metering),
            0x98 => Ok(FunctionCluster::Telephone),
            0xA0 => Ok(FunctionCluster::HealthServices),
            0xA8 => Ok(FunctionCluster::Warehouse),
            0xB0 => Ok(FunctionCluster::ElectronicTrade),
            0xB8 => Ok(FunctionCluster::Banking),
            0xC0 => Ok(FunctionCluster::EntertainmentSports),
            0xC8 => Ok(FunctionCluster::CarParking),
            0xC9 => Ok(FunctionCluster::FleetManagement),
            0xD0 => Ok(FunctionCluster::FuelGasoline),
            0xD8 => Ok(FunctionCluster::InfoServices),
            0xE0 => Ok(FunctionCluster::Press),
            0xE1 => Ok(FunctionCluster::NfcForum),
            0xE8 => Ok(FunctionCluster::Computer),
            0xF0 => Ok(FunctionCluster::Mail),
            0xF8 => Ok(FunctionCluster::MiscellaneousApplicationsF8),
            0xF9 => Ok(FunctionCluster::MiscellaneousApplicationsF9),
            0xFA => Ok(FunctionCluster::MiscellaneousApplicationsFA),
            0xFB => Ok(FunctionCluster::MiscellaneousApplicationsFB),
            0xFC => Ok(FunctionCluster::MiscellaneousApplicationsFC),
            0xFD => Ok(FunctionCluster::MiscellaneousApplicationsFD),
            0xFE => Ok(FunctionCluster::MiscellaneousApplicationsFE),
            0xFF => Ok(FunctionCluster::MiscellaneousApplicationsFF),
            _ => Err(MadAidError::InvalidFunctionCluster(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdministrationCode {
    Free = 0x00,
    Defect = 0x01,
    Reserved = 0x02,
    AdditionalDirectoryInfo = 0x03,
    CardholderInfo = 0x04,
    NotApplicable = 0x05,
}

impl TryFrom<u8> for AdministrationCode {
    type Error = MadAidError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AdministrationCode::Free),
            0x01 => Ok(AdministrationCode::Defect),
            0x02 => Ok(AdministrationCode::Reserved),
            0x03 => Ok(AdministrationCode::AdditionalDirectoryInfo),
            0x04 => Ok(AdministrationCode::CardholderInfo),
            0x05 => Ok(AdministrationCode::NotApplicable),
            _ => Err(MadAidError::InvalidAdministrationCode(value)),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MadAid {
    CardAdministration(AdministrationCode),
    Application(FunctionCluster, u8),
    Reserved(u8, u8),
}

impl MadAid {
    pub fn try_from_u8(function_cluster: u8, application_value: u8) -> Result<Self, MadAidError> {
        if function_cluster == 0 {
            Ok(MadAid::CardAdministration(AdministrationCode::try_from(
                application_value,
            )?))
        } else {
            if let Ok(fc) = FunctionCluster::try_from(function_cluster) {
                Ok(MadAid::Application(fc, application_value))
            } else {
                Ok(MadAid::Reserved(function_cluster, application_value))
            }
        }
    }

    pub fn try_from_u16(value: u16) -> Result<Self, MadAidError> {
        let function_cluster = (value >> 8) as u8;
        let application_value = value as u8;

        Self::try_from_u8(function_cluster, application_value)
    }

    pub fn to_u16(&self) -> u16 {
        let [function_cluster, application_code] = self.to_u8_slice();
        ((function_cluster as u16) << 8) | (application_code as u16)
    }

    pub fn to_u8_slice(&self) -> [u8; 2] {
        let (function_cluster, application_code) = match *self {
            MadAid::CardAdministration(admin_code) => (0, admin_code as u8),
            MadAid::Application(fc, app) => (fc as u8, app),
            MadAid::Reserved(fc, app) => (fc, app),
        };

        [function_cluster, application_code]
    }
}

#[derive(Debug)]
pub enum MadAidError {
    InvalidFunctionCluster(u8),
    InvalidAdministrationCode(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_cluster_to_u8() {
        assert_eq!(0x08, FunctionCluster::Airlines as u8);
        assert_eq!(0x4A, FunctionCluster::MinistryOfDefenceNl as u8);
        assert_eq!(0x90, FunctionCluster::Television as u8);
        assert_eq!(0xE1, FunctionCluster::NfcForum as u8);
        assert_eq!(0xFB, FunctionCluster::MiscellaneousApplicationsFB as u8);
    }

    #[test]
    fn u8_to_function_cluster() {
        assert_eq!(
            FunctionCluster::MiscellaneousApplications01,
            FunctionCluster::try_from(0x01).unwrap()
        );
        assert_eq!(
            FunctionCluster::MiscellaneousApplications07,
            FunctionCluster::try_from(0x07).unwrap()
        );
        assert_eq!(
            FunctionCluster::FerryTraffic,
            FunctionCluster::try_from(0x09).unwrap()
        );
        assert_eq!(
            FunctionCluster::MiscellaneousApplications11,
            FunctionCluster::try_from(0x11).unwrap()
        );
        assert_eq!(
            FunctionCluster::CzechRailways,
            FunctionCluster::try_from(0x19).unwrap()
        );
        assert_eq!(
            FunctionCluster::BusServices,
            FunctionCluster::try_from(0x20).unwrap()
        );
        assert_eq!(
            FunctionCluster::EuInstitutions,
            FunctionCluster::try_from(0x4C).unwrap()
        );
        assert_eq!(
            FunctionCluster::SoaaStandardOfflineAccess,
            FunctionCluster::try_from(0x55).unwrap()
        );
        assert_eq!(
            FunctionCluster::AcademicServices,
            FunctionCluster::try_from(0x58).unwrap()
        );
        assert_eq!(
            FunctionCluster::Food,
            FunctionCluster::try_from(0x60).unwrap()
        );
        assert_eq!(
            FunctionCluster::AirportServices,
            FunctionCluster::try_from(0x75).unwrap()
        );
        assert_eq!(
            FunctionCluster::Iopta,
            FunctionCluster::try_from(0x95).unwrap()
        );
        assert_eq!(
            FunctionCluster::Metering,
            FunctionCluster::try_from(0x97).unwrap()
        );
        assert_eq!(
            FunctionCluster::ElectronicTrade,
            FunctionCluster::try_from(0xB0).unwrap()
        );
        assert_eq!(
            FunctionCluster::Press,
            FunctionCluster::try_from(0xE0).unwrap()
        );
    }

    #[test]
    fn u8_to_invalid_function_cluster() {
        assert!(FunctionCluster::try_from(0x00).is_err());
        assert!(FunctionCluster::try_from(0x4F).is_err());
        assert!(FunctionCluster::try_from(0x57).is_err());
    }

    #[test]
    fn u8_to_function_cluster_to_u8() {
        for i in u8::MIN..=u8::MAX {
            if let Ok(f) = FunctionCluster::try_from(i) {
                assert_eq!(i, f as u8);
            }
        }
    }

    #[test]
    fn administration_code_to_u8() {
        assert_eq!(0x00, AdministrationCode::Free as u8);
        assert_eq!(0x01, AdministrationCode::Defect as u8);
        assert_eq!(0x02, AdministrationCode::Reserved as u8);
        assert_eq!(0x03, AdministrationCode::AdditionalDirectoryInfo as u8);
        assert_eq!(0x04, AdministrationCode::CardholderInfo as u8);
        assert_eq!(0x05, AdministrationCode::NotApplicable as u8);
    }

    #[test]
    fn u8_to_administration_code() {
        assert_eq!(
            AdministrationCode::Free,
            AdministrationCode::try_from(0x00).unwrap()
        );
        assert_eq!(
            AdministrationCode::Defect,
            AdministrationCode::try_from(0x01).unwrap()
        );
        assert_eq!(
            AdministrationCode::Reserved,
            AdministrationCode::try_from(0x02).unwrap()
        );
        assert_eq!(
            AdministrationCode::AdditionalDirectoryInfo,
            AdministrationCode::try_from(0x03).unwrap()
        );
        assert_eq!(
            AdministrationCode::CardholderInfo,
            AdministrationCode::try_from(0x04).unwrap()
        );
        assert_eq!(
            AdministrationCode::NotApplicable,
            AdministrationCode::try_from(0x05).unwrap()
        );
    }

    #[test]
    fn u8_to_invalid_administration_code() {
        for i in 6u8..u8::MAX {
            assert!(AdministrationCode::try_from(i).is_err());
        }
    }

    #[test]
    fn u8_to_administration_code_to_u8() {
        for i in u8::MIN..=u8::MAX {
            if let Ok(f) = AdministrationCode::try_from(i) {
                assert_eq!(i, f as u8);
            }
        }
    }

    #[test]
    fn mad_try_from_u8_valid_application() {
        for i in 1..=u8::MAX {
            if let Ok(_) = FunctionCluster::try_from(i) {
                for j in u8::MIN..=u8::MAX {
                    let aid = MadAid::try_from_u8(i, j).unwrap();
                    match aid {
                        MadAid::Application(f, a) => {
                            assert_eq!(i, f as u8);
                            assert_eq!(j, a);
                        }
                        _ => panic!("Expected application"),
                    }
                    let slice = aid.to_u8_slice();
                    assert_eq!(i, slice[0]);
                    assert_eq!(j, slice[1]);
                }
            }
        }
    }

    #[test]
    fn mad_try_from_u8_invalid_function_cluster() {
        for i in 1..=u8::MAX {
            if let Err(_) = FunctionCluster::try_from(i) {
                for j in u8::MIN..=u8::MAX {
                    match MadAid::try_from_u8(i, j) {
                        Ok(MadAid::Reserved(a, b)) => {
                            assert_eq!(i, a);
                            assert_eq!(j, b);
                        }
                        _ => panic!("Expected reserved application"),
                    }
                }
            }
        }
    }

    #[test]
    fn mad_try_from_u8_valid_admin_code() {
        for i in 1..=u8::MAX {
            if let Ok(_) = AdministrationCode::try_from(i) {
                let aid = MadAid::try_from_u8(0, i).unwrap();
                match aid {
                    MadAid::CardAdministration(a) => {
                        assert_eq!(i, a as u8);
                    }
                    _ => panic!("Expected card administration"),
                }
                let slice = aid.to_u8_slice();
                assert_eq!(0, slice[0]);
                assert_eq!(i, slice[1]);
            }
        }
    }

    #[test]
    fn mad_try_from_u16_valid() {
        let aid = MadAid::try_from_u16(0x4811).unwrap();
        match aid {
            MadAid::Application(fc, app) => {
                assert_eq!(FunctionCluster::AccessControlSecurity48, fc);
                assert_eq!(0x11, app);
            }
            _ => panic!("Expected application"),
        }

        let aid = MadAid::try_from_u16(0x4812).unwrap();
        match aid {
            MadAid::Application(fc, app) => {
                assert_eq!(FunctionCluster::AccessControlSecurity48, fc);
                assert_eq!(0x12, app);
            }
            _ => panic!("Expected application"),
        }

        for i in 1..=u16::MAX {
            let fc = (i >> 8) as u8;
            let app = i as u8;
            if let Ok(_) = FunctionCluster::try_from(fc) {
                let aid = MadAid::try_from_u16(i).unwrap();
                match aid {
                    MadAid::Application(f, a) => {
                        assert_eq!(fc, f as u8);
                        assert_eq!(app, a);
                    }
                    _ => panic!("Expected application"),
                }
                assert_eq!(i, aid.to_u16());
            }
        }
    }
}
