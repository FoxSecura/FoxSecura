// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use crate::database::{Database, DatabaseError};

pub struct AppData {
    database: Database,
}

impl AppData {
    pub fn open(database_path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        Ok(Self {
            database: Database::open(database_path)?,
        })
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    #[cfg(test)]
    fn from_database(database: Database) -> Self {
        Self { database }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::LATEST_SCHEMA_VERSION;

    #[test]
    fn app_data_owns_an_initialized_database() {
        let database = Database::open_in_memory().expect("la base en mémoire doit s'ouvrir");
        let data = AppData::from_database(database);

        assert_eq!(
            data.database()
                .schema_version()
                .expect("la version du schéma doit être lisible"),
            LATEST_SCHEMA_VERSION
        );
    }
}
