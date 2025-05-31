use std::error::Error as StdError;
use std::fmt;
use std::io;

use tokio_dl_stream_to_disk::error::Error as TDSTDError;
use tokio_dl_stream_to_disk::error::ErrorKind as TDSTDErrorKind;

/// Represents the specific kind of error that occurred within the `gpapi` library.
#[derive(Debug)]
pub enum ErrorKind {
    /// An error indicating that a file was expected to be created but already exists.
    FileExists,
    /// An error indicating that a directory was expected to be created but already exists.
    DirectoryExists,
    /// An error indicating that a required directory was not found or is not accessible.
    DirectoryMissing,
    /// An error related to an invalid application ID or issues with app-specific data during API interaction.
    InvalidApp,
    /// An error indicating that a security check, such as a CAPTCHA, is required to proceed.
    SecurityCheck,
    /// An error that occurred during the encryption of login credentials, often due to data length.
    EncryptLogin,
    /// An error indicating that an operation was denied due to insufficient permissions.
    PermissionDenied,
    /// An error indicating an invalid or unexpected response was received from the Google Play server.
    InvalidResponse,
    /// An underlying I/O error that occurred.
    IO(io::Error),
    /// An error represented by a simple string message, typically for custom error scenarios.
    Str(String),
    /// A boxed, dynamically dispatched error from another source.
    Other(Box<dyn StdError>),
}

/// Represents an error that can occur while using the `gpapi` library.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Creates a new `Error` with the specified `ErrorKind`.
    pub fn new(kind: ErrorKind) -> Self {
        Error { kind }
    }

    /// Returns a reference to the `ErrorKind` for this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::new(ErrorKind::IO(err))
    }
}

impl From<Box<dyn StdError>> for Error {
    fn from(err: Box<dyn StdError>) -> Self {
        Error::new(ErrorKind::Other(err))
    }
}

/// Converts a `tokio-dl-stream-to-disk::Error` into a `gpapi::Error`.
/// This allows for unified error handling from download operations.
impl From<TDSTDError> for Error {
    fn from(err: TDSTDError) -> Self {
        let kind = match err.kind() {
            TDSTDErrorKind::FileExists => ErrorKind::FileExists,
            TDSTDErrorKind::DirectoryMissing => ErrorKind::DirectoryMissing,
            TDSTDErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            TDSTDErrorKind::InvalidResponse => ErrorKind::InvalidResponse,
            TDSTDErrorKind::IO(_) => ErrorKind::IO(
                err.into_inner_io()
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "Unknown TDSTD I/O error")),
            ),
            TDSTDErrorKind::Other(_) => ErrorKind::Other(
                err.into_inner_other()
                    .unwrap_or_else(|| Box::new(fmt::Error) as Box<dyn StdError>),
            ),
        };
        Error::new(kind)
    }
}

impl From<&str> for Error {
    fn from(err_msg: &str) -> Self {
        Error::new(ErrorKind::Str(err_msg.to_string()))
    }
}

impl From<String> for Error {
    fn from(err_msg: String) -> Self {
        Error::new(ErrorKind::Str(err_msg))
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
            (ErrorKind::Str(a), ErrorKind::Str(b)) => a == b,
            (ErrorKind::IO(a), ErrorKind::IO(b)) => a.kind() == b.kind(),
            (ErrorKind::Other(_), ErrorKind::Other(_)) => {
                true // Simplified comparison for test purposes
            }
            _ => false,
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.kind {
            ErrorKind::IO(ref err) => Some(err),
            ErrorKind::Other(ref err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind() {
            ErrorKind::FileExists => write!(f, "File already exists."),
            ErrorKind::DirectoryExists => write!(f, "Directory already exists."),
            ErrorKind::DirectoryMissing => write!(f, "The provided destination path is not a valid directory."),
            ErrorKind::InvalidApp => write!(f, "Invalid app response from Google Play."),
            ErrorKind::SecurityCheck => write!(f, "Security check is needed. Try visiting https://accounts.google.com/b/0/DisplayUnlockCaptcha to unlock, or set up an app-specific password."),
            ErrorKind::EncryptLogin => write!(f, "Error encrypting login information: The login and password combination is too long. Please use a shorter password or an app-specific password."),
            ErrorKind::PermissionDenied => write!(f, "Operation denied due to insufficient permissions."),
            ErrorKind::InvalidResponse => write!(f, "Invalid or unexpected response from the remote host."),
            ErrorKind::IO(err) => write!(f, "I/O error: {}", err),
            ErrorKind::Str(err_msg) => write!(f, "{}", err_msg),
            ErrorKind::Other(err) => write!(f, "An external error occurred: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use std::io::{self, ErrorKind as IOErrorKind};
    use std::fmt;
    use std::error::Error as StdError;

    #[test]
    fn test_display_file_exists() {
        assert_eq!(Error::new(ErrorKind::FileExists).to_string(), "File already exists.", "Display for FileExists mismatch");
    }
    #[test]
    fn test_display_directory_exists() {
        assert_eq!(Error::new(ErrorKind::DirectoryExists).to_string(), "Directory already exists.", "Display for DirectoryExists mismatch");
    }
    #[test]
    fn test_display_directory_missing() {
        assert_eq!(Error::new(ErrorKind::DirectoryMissing).to_string(), "The provided destination path is not a valid directory.", "Display for DirectoryMissing mismatch");
    }
    #[test]
    fn test_display_invalid_app() {
        assert_eq!(Error::new(ErrorKind::InvalidApp).to_string(), "Invalid app response from Google Play.", "Display for InvalidApp mismatch");
    }
    #[test]
    fn test_display_security_check() {
        assert_eq!(Error::new(ErrorKind::SecurityCheck).to_string(), "Security check is needed. Try visiting https://accounts.google.com/b/0/DisplayUnlockCaptcha to unlock, or set up an app-specific password.", "Display for SecurityCheck mismatch");
    }
    #[test]
    fn test_display_encrypt_login() {
        assert_eq!(Error::new(ErrorKind::EncryptLogin).to_string(), "Error encrypting login information: The login and password combination is too long. Please use a shorter password or an app-specific password.", "Display for EncryptLogin mismatch");
    }
    #[test]
    fn test_display_permission_denied() {
        assert_eq!(Error::new(ErrorKind::PermissionDenied).to_string(), "Operation denied due to insufficient permissions.", "Display for PermissionDenied mismatch");
    }
    #[test]
    fn test_display_invalid_response() {
        assert_eq!(Error::new(ErrorKind::InvalidResponse).to_string(), "Invalid or unexpected response from the remote host.", "Display for InvalidResponse mismatch");
    }
    #[test]
    fn test_display_io_error() {
        let io_err = io::Error::new(IOErrorKind::Other, "custom io display test");
        assert_eq!(Error::new(ErrorKind::IO(io_err)).to_string(), "I/O error: custom io display test", "Display for IO error mismatch");
    }
    #[test]
    fn test_display_str_error() {
        assert_eq!(Error::new(ErrorKind::Str("custom str display test".to_string())).to_string(), "custom str display test", "Display for Str error mismatch");
    }
    #[test]
    fn test_display_other_error() {
        #[derive(Debug)] struct MyDisplayTestError(&'static str);
        impl fmt::Display for MyDisplayTestError { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) } }
        impl StdError for MyDisplayTestError {}
        let other_err = Box::new(MyDisplayTestError("custom other display test"));
        assert_eq!(Error::new(ErrorKind::Other(other_err)).to_string(), "An external error occurred: custom other display test", "Display for Other error mismatch");
    }

    #[test]
    fn test_error_source_method() { // Renamed for clarity
        // Test source for ErrorKind::IO
        let io_err_inner = io::Error::new(IOErrorKind::PermissionDenied, "io source test");
        let error_io = Error::new(ErrorKind::IO(io_err_inner)); // io_err_inner is moved here
        let io_err_inner_for_assert = io::Error::new(IOErrorKind::PermissionDenied, "io source test"); // Recreate for assertion comparison
        match error_io.source() {
            Some(source) => assert_eq!(source.to_string(), io_err_inner_for_assert.to_string(), "Source for IO error mismatch"),
            None => panic!("ErrorKind::IO should have a source"),
        }


        // Test source for ErrorKind::Other
        #[derive(Debug)] struct MyCustomSourceError(&'static str);
        impl fmt::Display for MyCustomSourceError { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) } }
        impl StdError for MyCustomSourceError {}
        let other_err_inner_boxed = Box::new(MyCustomSourceError("other source test")) as Box<dyn StdError>;
        let error_other = Error::new(ErrorKind::Other(other_err_inner_boxed));
         match error_other.source() {
            Some(source) => assert_eq!(source.to_string(), "other source test", "Source for Other error mismatch"),
            None => panic!("ErrorKind::Other should have a source"),
        }


        // Test source for variants without an inner error
        assert!(Error::new(ErrorKind::FileExists).source().is_none(), "ErrorKind::FileExists should not have a source");
        assert!(Error::new(ErrorKind::Str("some string error".to_string())).source().is_none(), "ErrorKind::Str should not have a source");
    }

    #[test]
    fn test_from_trait_implementations() { // Renamed
        // Test From<io::Error>
        let io_error = io::Error::new(IOErrorKind::NotFound, "file not found for from");
        let error_from_io = Error::from(io_error); // io_error is moved
        match error_from_io.kind() {
            ErrorKind::IO(e) => assert_eq!(e.kind(), IOErrorKind::NotFound, "From<io::Error> kind mismatch"),
            _ => panic!("Expected ErrorKind::IO from io::Error conversion"),
        }

        // Test From<&str>
        let str_slice_error_msg = "this is a &str error";
        let error_from_str_slice = Error::from(str_slice_error_msg);
        match error_from_str_slice.kind() {
            ErrorKind::Str(s) => assert_eq!(s, str_slice_error_msg, "From<&str> message mismatch"),
            _ => panic!("Expected ErrorKind::Str from &str conversion"),
        }

        // Test From<String>
        let string_error_msg = String::from("this is a String error");
        let error_from_string = Error::from(string_error_msg.clone()); // Clone if string_error_msg is used later
        match error_from_string.kind() {
            ErrorKind::Str(s) => assert_eq!(s, &string_error_msg, "From<String> message mismatch"),
            _ => panic!("Expected ErrorKind::Str from String conversion"),
        }

        // Test From<Box<dyn StdError>>
        #[derive(Debug)] struct MyBoxedStdError(&'static str);
        impl fmt::Display for MyBoxedStdError { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) } }
        impl StdError for MyBoxedStdError {}
        let boxed_dyn_std_error_msg = "this is a boxed dyn error";
        let boxed_dyn_error = Box::new(MyBoxedStdError(boxed_dyn_std_error_msg)) as Box<dyn StdError>;
        let error_from_boxed_dyn = Error::from(boxed_dyn_error);
        match error_from_boxed_dyn.kind() {
            ErrorKind::Other(e) => assert_eq!(e.to_string(), boxed_dyn_std_error_msg, "From<Box<dyn StdError>> message mismatch"),
            _ => panic!("Expected ErrorKind::Other from Box<dyn StdError> conversion"),
        }
    }

    #[test]
    fn test_partial_equality_for_error_kind() { // Renamed
        assert_eq!(ErrorKind::FileExists, ErrorKind::FileExists, "FileExists should be equal to itself");
        assert_ne!(ErrorKind::FileExists, ErrorKind::DirectoryExists, "FileExists should not be equal to DirectoryExists");

        assert_eq!(ErrorKind::Str("hello".to_string()), ErrorKind::Str("hello".to_string()), "Str a==a failed");
        assert_ne!(ErrorKind::Str("hello".to_string()), ErrorKind::Str("world".to_string()), "Str a==b failed");

        // Test IO: PartialEq for ErrorKind::IO compares io::Error::kind()
        let io_err1_notfound = io::Error::new(IOErrorKind::NotFound, "e1");
        let io_err2_notfound_again = io::Error::new(IOErrorKind::NotFound, "e2_different_message");
        let io_err3_permission = io::Error::new(IOErrorKind::PermissionDenied, "e3");

        assert_eq!(ErrorKind::IO(io_err1_notfound), ErrorKind::IO(io_err2_notfound_again), "IO(NotFound) should be equal regardless of message");

        let io_err1_notfound_for_ne = io::Error::new(IOErrorKind::NotFound, "e1_for_ne"); // Recreate to avoid move
        assert_ne!(ErrorKind::IO(io_err1_notfound_for_ne), ErrorKind::IO(io_err3_permission), "IO(NotFound) should not be equal to IO(PermissionDenied)");

        // Test Other: PartialEq for ErrorKind::Other simply returns true if both are Other.
        let other_err_fmt1 = Box::new(fmt::Error) as Box<dyn StdError>;
        let other_err_fmt2 = Box::new(fmt::Error) as Box<dyn StdError>;
        assert_eq!(ErrorKind::Other(other_err_fmt1), ErrorKind::Other(other_err_fmt2), "Other(fmt::Error) instances should compare as equal by type");
    }
}
