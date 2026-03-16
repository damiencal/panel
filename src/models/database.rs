use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum DatabaseType {
    #[serde(rename = "MariaDB")]
    #[cfg_attr(feature = "server", sqlx(rename = "MariaDB"))]
    MariaDB,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::MariaDB => write!(f, "MariaDB"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "server", derive(sqlx::Type))]
#[cfg_attr(feature = "server", sqlx(type_name = "TEXT"))]
pub enum DatabaseStatus {
    #[serde(rename = "Active")]
    Active,
    #[serde(rename = "Suspended")]
    Suspended,
    #[serde(rename = "Inactive")]
    Inactive,
}

impl std::fmt::Display for DatabaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseStatus::Active => write!(f, "Active"),
            DatabaseStatus::Suspended => write!(f, "Suspended"),
            DatabaseStatus::Inactive => write!(f, "Inactive"),
        }
    }
}

/// Database instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct Database {
    pub id: i64,
    pub owner_id: i64,
    pub name: String,
    pub database_type: DatabaseType,
    pub status: DatabaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database user with credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "server", derive(sqlx::FromRow))]
pub struct DatabaseUser {
    pub id: i64,
    pub database_id: i64,
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    pub privileges: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDatabaseRequest {
    pub name: String,
    pub database_type: DatabaseType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDatabaseUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseWithUsers {
    pub database: Database,
    pub users: Vec<DatabaseUser>,
}
