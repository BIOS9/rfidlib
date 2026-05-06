use crate::mifare::desfire::key::KeyNumber;

/// Access conditions for a `DESFire` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    read: Option<KeyNumber>,
    write: Option<KeyNumber>,
    read_write: Option<KeyNumber>,
    change: Option<KeyNumber>,
}

impl AccessRights {
    /// Creates access rights from optional key requirements.
    pub const fn new(
        read: Option<KeyNumber>,
        write: Option<KeyNumber>,
        read_write: Option<KeyNumber>,
        change: Option<KeyNumber>,
    ) -> Self {
        Self {
            read,
            write,
            read_write,
            change,
        }
    }

    /// Required key for read access, or `None` when access is free/never.
    pub const fn read(self) -> Option<KeyNumber> {
        self.read
    }

    /// Required key for write access, or `None` when access is free/never.
    pub const fn write(self) -> Option<KeyNumber> {
        self.write
    }

    /// Required key for combined read/write access, or `None` when access is free/never.
    pub const fn read_write(self) -> Option<KeyNumber> {
        self.read_write
    }

    /// Required key for changing file settings, or `None` when access is free/never.
    pub const fn change(self) -> Option<KeyNumber> {
        self.change
    }
}
