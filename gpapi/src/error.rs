use std::error::Error as StdError;
use std::fmt;
use std::io::Error as IOError;

use tokio_dl_stream_to_disk::error::Error as TDSTDError;
use tokio_dl_stream_to_disk::error::ErrorKind as TDSTDErrorKind;

#[derive(Debug)]
pub enum ErrorKind {
    FileExists,
    DirectoryExists,
    DirectoryMissing,
    InvalidApp,
    SecurityCheck,
    EncryptLogin,
    PermissionDenied,
    InvalidResponse,
    IO(IOError),
    Str(String),
    Other(Box<dyn StdError>),
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(k: ErrorKind) -> Error {
        Error { kind: k }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<IOError> for Error {
    fn from(err: IOError) -> Error {
        Error {
            kind: ErrorKind::IO(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use std::io;
    // We need a type that implements std::error::Error for the Other variant.
    // std::fmt::Error is a simple type that does this.
    use std::fmt;

    #[test]
    fn test_error_display_formatting() {
        // Test ErrorKind::FileExists
        let error_file_exists = Error::new(ErrorKind::FileExists);
        assert_eq!(format!("{}", error_file_exists), "File already exists");

        // Test ErrorKind::InvalidApp
        let error_invalid_app = Error::new(ErrorKind::InvalidApp);
        assert_eq!(format!("{}", error_invalid_app), "Invalid app response");

        // Test ErrorKind::DirectoryExists
        let error_dir_exists = Error::new(ErrorKind::DirectoryExists);
        assert_eq!(format!("{}", error_dir_exists), "Directory already exists");

        // Test ErrorKind::DirectoryMissing
        let error_dir_missing = Error::new(ErrorKind::DirectoryMissing);
        assert_eq!(format!("{}", error_dir_missing), "Destination path provided is not a valid directory");

        // Test ErrorKind::SecurityCheck
        let error_security_check = Error::new(ErrorKind::SecurityCheck);
        assert_eq!(format!("{}", error_security_check), "Security check is needed, try to visit https://accounts.google.com/b/0/DisplayUnlockCaptcha to unlock, or setup an app-specific password");

        // Test ErrorKind::EncryptLogin
        let error_encrypt_login = Error::new(ErrorKind::EncryptLogin);
        assert_eq!(format!("{}", error_encrypt_login), "Error encrypting login information: login + password combination is too long. Please use a shorter or app-specific password");

        // Test ErrorKind::PermissionDenied
        let error_perm_denied = Error::new(ErrorKind::PermissionDenied);
        assert_eq!(format!("{}", error_perm_denied), "Cannot create file: permission denied");

        // Test ErrorKind::InvalidResponse
        let error_invalid_resp = Error::new(ErrorKind::InvalidResponse);
        assert_eq!(format!("{}", error_invalid_resp), "Invalid response from the remote host");

        // Test ErrorKind::IO
        let io_err_inner = io::Error::new(io::ErrorKind::Other, "test io error");
        let error_io = Error::new(ErrorKind::IO(io_err_inner));
        assert_eq!(format!("{}", error_io), "test io error");

        // Test ErrorKind::Str
        let str_err_inner = "test str error".to_string();
        let error_str = Error::new(ErrorKind::Str(str_err_inner));
        assert_eq!(format!("{}", error_str), "test str error");

        // Test ErrorKind::Other
        // std::fmt::Error is a simple type that implements std::error::Error and Display.
        // Its Display impl returns "an error occurred when formatting an argument".
        let other_err_inner = Box::new(fmt::Error);
        let error_other = Error::new(ErrorKind::Other(other_err_inner));
        assert_eq!(format!("{}", error_other), "an error occurred when formatting an argument");
    }
}

impl From<Box<dyn StdError>> for Error {
    fn from(err: Box<dyn StdError>) -> Error {
        Error {
            kind: ErrorKind::Other(err),
        }
    }
}

impl From<TDSTDError> for Error {
    fn from(err: TDSTDError) -> Error {
        match err.kind() {
            TDSTDErrorKind::FileExists => Error {
                kind: ErrorKind::FileExists,
            },
            TDSTDErrorKind::DirectoryMissing => Error {
                kind: ErrorKind::DirectoryMissing,
            },
            TDSTDErrorKind::PermissionDenied => Error {
                kind: ErrorKind::PermissionDenied,
            },
            TDSTDErrorKind::InvalidResponse => Error {
                kind: ErrorKind::InvalidResponse,
            },
            TDSTDErrorKind::IO(_) => {
                let err = err.into_inner_io().unwrap();
                Error {
                    kind: ErrorKind::IO(err),
                }
            }
            TDSTDErrorKind::Other(_) => {
                let err = err.into_inner_other().unwrap();
                Error {
                    kind: ErrorKind::Other(err),
                }
            }
        }
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error {
            kind: ErrorKind::Str(err.to_string()),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error {
            kind: ErrorKind::Str(err),
        }
    }
}

impl PartialEq for ErrorKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ErrorKind::FileExists, ErrorKind::FileExists) => true,
            (ErrorKind::DirectoryExists, ErrorKind::DirectoryExists) => true,
            (ErrorKind::DirectoryMissing, ErrorKind::DirectoryMissing) => true,
            (ErrorKind::InvalidApp, ErrorKind::InvalidApp) => true,
            (ErrorKind::SecurityCheck, ErrorKind::SecurityCheck) => true,
            (ErrorKind::EncryptLogin, ErrorKind::EncryptLogin) => true,
            (ErrorKind::PermissionDenied, ErrorKind::PermissionDenied) => true,
            (ErrorKind::InvalidResponse, ErrorKind::InvalidResponse) => true,
            (ErrorKind::IO(_), ErrorKind::IO(_)) => true, // Intentionally not comparing inner error
            (ErrorKind::Str(a), ErrorKind::Str(b)) => a == b,
            (ErrorKind::Other(_), ErrorKind::Other(_)) => true, // Intentionally not comparing inner error
            _ => false,
        }
    }
}

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind() {
            ErrorKind::FileExists => write!(f, "File already exists"),
            ErrorKind::InvalidApp => write!(f, "Invalid app response"),
            ErrorKind::DirectoryExists => write!(f, "Directory already exists"),
            ErrorKind::DirectoryMissing => write!(f, "Destination path provided is not a valid directory"),
            ErrorKind::SecurityCheck => write!(f, "Security check is needed, try to visit https://accounts.google.com/b/0/DisplayUnlockCaptcha to unlock, or setup an app-specific password"),
            ErrorKind::EncryptLogin => write!(f, "Error encrypting login information: login + password combination is too long. Please use a shorter or app-specific password"),
            ErrorKind::PermissionDenied => write!(f, "Cannot create file: permission denied"),
            ErrorKind::InvalidResponse => write!(f, "Invalid response from the remote host"),
            ErrorKind::IO(err) => err.fmt(f),
            ErrorKind::Str(err) => err.fmt(f),
            ErrorKind::Other(err) => err.fmt(f),
        }
    }
}
