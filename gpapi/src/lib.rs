//! A library for interacting with the Google Play API, strongly following [google play python API](https://github.com/NoMore200/googleplay-api.git) patterns.
//!
//! # Getting Started
//!
//! Interacting with the API starts off with initializing the API and logging in.
//!
//! ```rust
//! use gpapi::Gpapi;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut gpa = Gpapi::new("en_US", "UTC", "hero2lte");
//!     // Replace with valid credentials for testing, or ensure login is handled if running examples.
//!     // gpa.login("someone@gmail.com", "somepass").await.expect("Login failed");
//!     // do something
//! }
//! ```
//!
//! From here, you can get package details, get the info to download a package, or use the library to download it.
//!
//! ```rust
//! # use gpapi::Gpapi;
//! # use std::path::Path;
//! # #[tokio::main]
//! # async fn main() {
//! # let mut gpa = Gpapi::new("en_US", "UTC", "hero2lte");
//! # // The following lines would require a valid login to succeed.
//! # // For documentation purposes, we assume `gpa` is authenticated.
//! # // In a real application, you would call gpa.login("email", "password").await first.
//! # async { // Added async block for await
//! let details = gpa.details("com.instagram.android").await;
//! // println!("{:?}", details); // Commented out to avoid too much output
//!
//! let download_info = gpa.get_download_info("com.instagram.android", None).await;
//! // println!("{:?}", download_info); // Commented out
//!
//! // Ensure /tmp/testing directory exists or use a valid path for testing downloads.
//! // gpa.download("com.instagram.android", None, true, true, &Path::new("/tmp/testing"), None).await.expect("Download failed");
//! # };
//! # }
//! ```

mod consts;
pub mod error;

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH, SystemTimeError as StdSystemTimeError};

use base64::{Engine as _, engine::general_purpose as b64_general_purpose};
use bytes::Bytes;
// futures::future::TryFutureExt is not used after map_err changes.
// use futures::future::TryFutureExt;
use hyper::client::HttpConnector;
use hyper::header::{HeaderName as HyperHeaderName, HeaderValue as HyperHeaderValue};
use hyper::{Body, Client, Method, Request as HyperRequest};
use hyper_openssl::HttpsConnector;
use openssl::error::ErrorStack as OpenSslErrorStack;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use openssl::ssl::{SslConnector, SslMethod};
use prost::{Message, DecodeError as ProstDecodeError, EncodeError as ProstEncodeError};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Url;
// TokioDlError alias removed as the closure will accept Box<dyn StdError>
use tokio_dl_stream_to_disk::AsyncDownload;


use crate::error::{Error as GpapiError, ErrorKind as GpapiErrorKind};

use googleplay_protobuf::{
    AndroidCheckinProto, AndroidCheckinRequest, AndroidCheckinResponse, BulkDetailsRequest,
    BulkDetailsResponse, DetailsResponse, DeviceConfigurationProto, ResponseWrapper,
    UploadDeviceConfigRequest, UploadDeviceConfigResponse,
};

#[macro_use]
extern crate lazy_static;

static DEVICES_ENCODED: &[u8] = include_bytes!("device_properties.bin");
static CHECKINS_ENCODED: &[u8] = include_bytes!("android_checkins.bin");
lazy_static! {
    static ref DEVICE_CONFIGURATIONS: HashMap<String, Vec<u8>> =
        bincode::deserialize(DEVICES_ENCODED).expect("Failed to deserialize device configurations");
    static ref ANDROID_CHECKINS: HashMap<String, Vec<u8>> =
        bincode::deserialize(CHECKINS_ENCODED).expect("Failed to deserialize android checkins");
}

type MainAPKDownloadURL = Option<String>;
type SplitsDownloadInfo = Vec<(Option<String>, Option<String>)>;
type AdditionalFilesDownloadInfo = Vec<(Option<String>, Option<String>)>;
type DownloadInfo = (MainAPKDownloadURL, SplitsDownloadInfo, AdditionalFilesDownloadInfo);

/// Represents the main interface for interacting with the Google Play API.
#[derive(Debug)]
pub struct Gpapi {
    locale: String,
    timezone: String,
    device_codename: String,
    pub(crate) auth_subtoken: Option<String>,
    pub(crate) device_config_token: Option<String>,
    pub(crate) device_checkin_consistency_token: Option<String>,
    dfe_cookie: Option<String>,
    gsf_id: Option<i64>,
    client: Box<reqwest::Client>,
    hyper_client: Box<hyper::Client<HttpsConnector<HttpConnector>>>,
}

impl Gpapi {
    /// Creates a new `Gpapi` instance.
    pub fn new<S: Into<String>>(locale: S, timezone: S, device_codename: S) -> Self {
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls())
            .expect("Failed to create SSL connector builder");
        ssl_connector_builder
            .set_cipher_list(consts::GOOGLE_ACCEPTED_CIPHERS)
            .expect("Failed to set cipher list");
        let https_connector = HttpsConnector::with_connector(http_connector, ssl_connector_builder)
            .expect("Failed to create HttpsConnector");
        let hyper_client = Client::builder().build::<_, hyper::Body>(https_connector);

        Gpapi {
            locale: locale.into(),
            timezone: timezone.into(),
            device_codename: device_codename.into(),
            auth_subtoken: None,
            device_config_token: None,
            device_checkin_consistency_token: None,
            dfe_cookie: None,
            gsf_id: None,
            client: Box::new(reqwest::Client::new()),
            hyper_client: Box::new(hyper_client),
        }
    }

    /// Authenticates with Google Play services.
    pub async fn login<S: Into<String> + Clone>(
        &mut self,
        email: S,
        password: S,
    ) -> Result<(), GpapiError> {
        let email_str: String = email.into();
        let password_str: String = password.into();

        let encrypted_login_payload = encrypt_login(&email_str, &password_str)?;
        let b64_encrypted_login = b64_general_purpose::URL_SAFE_NO_PAD.encode(&encrypted_login_payload);

        let auth_response_map = self.authenticate(&email_str, &b64_encrypted_login)
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        if let Some(error_msg) = auth_response_map.get("error") {
            if error_msg == "NeedsBrowser" {
                return Err(GpapiError::new(GpapiErrorKind::SecurityCheck));
            }
            return Err(GpapiError::new(GpapiErrorKind::Str(format!("Authentication failed: {}", error_msg))));
        }

        let master_token = auth_response_map.get("auth")
            .ok_or_else(|| GpapiError::new(GpapiErrorKind::Str("No 'auth' (master token) in authentication response".to_string())))?
            .to_string();

        self.gsf_id = self.checkin(&email_str, &master_token)
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        if self.gsf_id.is_none() {
            return Err(GpapiError::new(GpapiErrorKind::Str("Failed to obtain GSF ID during check-in".to_string())));
        }

        self.get_auth_subtoken(&email_str, &b64_encrypted_login)
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        if self.auth_subtoken.is_none() {
            return Err(GpapiError::new(GpapiErrorKind::Str("Failed to obtain auth_subtoken".to_string())));
        }

        let upload_config_response = self.upload_device_config()
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        if let Some(token_response) = upload_config_response {
            if let Some(token_val) = token_response.upload_device_config_token {
                self.device_config_token = Some(token_val);
                Ok(())
            } else {
                Err(GpapiError::new(GpapiErrorKind::Str("No device_config_token in upload_device_config response".to_string())))
            }
        } else {
            Err(GpapiError::new(GpapiErrorKind::Str("Failed to upload device configuration or parse response".to_string())))
        }
    }

    /// Performs the Android device check-in process.
    async fn checkin(
        &mut self,
        email: &str,
        ac2dm_token: &str,
    ) -> Result<Option<i64>, Box<dyn StdError>> {
        let mut base_checkin_proto = ANDROID_CHECKINS
            .get(&self.device_codename)
            .map(|raw_proto_bytes| AndroidCheckinProto::decode(&mut Cursor::new(raw_proto_bytes.clone())))
            .ok_or_else(|| Box::new(GpapiError::new(GpapiErrorKind::Str(format!("Invalid device codename for checkin: {}", self.device_codename)))) as Box<dyn StdError>)?
            .map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;

        base_checkin_proto.build.as_mut().map_or(Ok::<(), Box<dyn StdError>>(()), |build_info| {
            build_info.timestamp = Some(SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e_sys| Box::new(e_sys) as Box<dyn StdError>)?
                .as_secs() as i64);
            Ok::<(), Box<dyn StdError>>(())
        })?;

        let mut initial_checkin_request = AndroidCheckinRequest::default();
        initial_checkin_request.id = Some(0);
        initial_checkin_request.checkin = Some(base_checkin_proto.clone());
        initial_checkin_request.locale = Some(self.locale.clone());
        initial_checkin_request.time_zone = Some(self.timezone.clone());
        initial_checkin_request.version = Some(3);
        initial_checkin_request.device_configuration = DEVICE_CONFIGURATIONS
            .get(&self.device_codename)
            .map(|raw_config_bytes| DeviceConfigurationProto::decode(&mut Cursor::new(raw_config_bytes.clone())))
            .transpose()
            .map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;
        initial_checkin_request.fragment = Some(0);

        let mut request_bytes = Vec::new();
        initial_checkin_request.encode(&mut request_bytes).map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;

        let initial_response = self.execute_checkin_request(&request_bytes).await?;
        self.device_checkin_consistency_token = initial_response.device_checkin_consistency_token.clone();

        let mut followup_checkin_request = initial_checkin_request;
        followup_checkin_request.id = initial_response.android_id.map(|id| id as i64);
        followup_checkin_request.security_token = initial_response.security_token;
        followup_checkin_request.account_cookie.push(format!("[{}]", email));
        followup_checkin_request.account_cookie.push(ac2dm_token.to_string());

        request_bytes.clear();
        followup_checkin_request.encode(&mut request_bytes).map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;

        let followup_response = self.execute_checkin_request(&request_bytes).await?;
        Ok(followup_response.android_id.map(|id| id as i64))
    }

    /// Uploads device configuration to Google Play.
    async fn upload_device_config(
        &self,
    ) -> Result<Option<UploadDeviceConfigResponse>, Box<dyn StdError>> {
        let mut upload_config_request_proto = UploadDeviceConfigRequest::default();
        upload_config_request_proto.device_configuration = DEVICE_CONFIGURATIONS
            .get(&self.device_codename)
            .map(|raw_config_bytes| DeviceConfigurationProto::decode(&mut Cursor::new(raw_config_bytes.clone())))
            .transpose()
            .map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;

        let mut request_bytes = Vec::new();
        upload_config_request_proto.encode(&mut request_bytes).map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)?;

        let mut request_headers = HeaderMap::new();
        request_headers.insert("X-DFE-Enabled-Experiments", HeaderValue::from_static("cl:billing.select_add_instrument_by_default"));
        request_headers.insert("X-DFE-Unsupported-Experiments", HeaderValue::from_static("nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes"));
        request_headers.insert("X-DFE-SmallestScreenWidthDp", HeaderValue::from_static("320"));
        request_headers.insert("X-DFE-Filter-Level", HeaderValue::from_static("3"));

        let response_wrapper = self.execute_request_v2("uploadDeviceConfig", None, Some(&request_bytes), request_headers).await?;

        Ok(response_wrapper.payload.and_then(|p| p.upload_device_config_response))
    }

    /// Downloads an app's APK and any additional files.
    pub async fn download<S: Into<String>>(
        &self,
        pkg_name: S,
        version_code: Option<i32>,
        split_if_available: bool,
        include_additional_files: bool,
        dst_path: &Path,
        cb: Option<&Box<dyn Fn(String, u64) -> Box<dyn Fn(u64) -> ()>>>,
    ) -> Result<Vec<()>, GpapiError> {
        let pkg_name_str: String = pkg_name.into();
        let download_info_result = self
            .get_download_info(pkg_name_str.clone(), version_code)
            .await?;

        let mut actual_dst_path = PathBuf::from(dst_path);
        if actual_dst_path.is_dir() {
            if (split_if_available && !download_info_result.1.is_empty()) ||
               (include_additional_files && !download_info_result.2.is_empty()){
                actual_dst_path.push(pkg_name_str.clone());
                if actual_dst_path.is_dir() {
                    return Err(GpapiError::new(GpapiErrorKind::DirectoryExists));
                } else {
                    fs::create_dir(&actual_dst_path).map_err(GpapiError::from)?;
                }
            }
        } else {
            return Err(GpapiError::new(GpapiErrorKind::DirectoryMissing));
        }

        let mut downloads = Vec::new();
        let map_download_error = |e: Box<dyn StdError>| GpapiError::new(GpapiErrorKind::Other(e));

        if include_additional_files && !download_info_result.2.is_empty() {
            for additional_file_info in download_info_result.2 {
                if let (Some(filename), Some(download_url)) = additional_file_info {
                    let dl = AsyncDownload::new(&download_url, &actual_dst_path, &filename).get().await.map_err(map_download_error)?;
                    let length = dl.length();
                    let progress_callback = length.and_then(|l| cb.map(|callb| callb(filename.clone(), l)));
                    downloads.push((dl, progress_callback));
                }
            }
        }

        if split_if_available && !download_info_result.1.is_empty() {
            for split_info in download_info_result.1 {
                if let (Some(download_name), Some(download_url)) = split_info {
                    let filename = format!("{}.{}.apk", pkg_name_str, download_name);
                    let dl = AsyncDownload::new(&download_url, &actual_dst_path, &filename).get().await.map_err(map_download_error)?;
                    let length = dl.length();
                    let progress_callback = length.and_then(|l| cb.map(|callb| callb(filename.clone(), l)));
                    downloads.push((dl, progress_callback));
                }
            }
        }

        let main_apk_filename = format!("{}.apk", pkg_name_str);
        if let Some(main_apk_download_url) = download_info_result.0 {
            let dl = AsyncDownload::new(&main_apk_download_url, &actual_dst_path, &main_apk_filename).get().await.map_err(map_download_error)?;
            let length = dl.length();
            let progress_callback = length.and_then(|l| cb.map(|callb| callb(main_apk_filename.clone(), l)));
            downloads.push((dl, progress_callback));
        } else {
            return Err(GpapiError::new(GpapiErrorKind::Str("Could not download app - no main APK download URL available".to_string())));
        }

        futures::future::try_join_all(downloads.iter_mut().map(|(d, c)| {
            async {
                d.download(c).await.map_err(GpapiError::from) // Assumes GpapiError::from can handle TokioDlError
            }
        })).await
    }

    /// Fetches download information for a package.
    pub async fn get_download_info<S: Into<String>>(
        &self,
        pkg_name: S,
        mut version_code: Option<i32>,
    ) -> Result<DownloadInfo, GpapiError> {
        let package_name_str: String = pkg_name.into();
        if self.auth_subtoken.is_none() {
            return Err(GpapiError::new(GpapiErrorKind::Str("User not logged in. Call login() first.".to_string())));
        }
        if version_code.is_none() {
            version_code = Some(self.get_latest_version_for_pkg_name(&package_name_str).await?);
        }

        let actual_version_code = version_code.expect("Version code should be present here");
        let purchase_response_wrapper = {
            let version_code_string = actual_version_code.to_string();
            let mut request_params = HashMap::new();
            request_params.insert("ot", "1");
            request_params.insert("doc", package_name_str.as_str());
            request_params.insert("vc", &version_code_string);
            self.execute_request_v2("purchase", Some(request_params), None, HeaderMap::new())
                .await
                .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?
        };

        let download_token = purchase_response_wrapper.payload
            .and_then(|p| p.buy_response)
            .and_then(|br| br.download_token)
            .ok_or_else(|| GpapiError::new(GpapiErrorKind::Str(
                "Failed to obtain download token from purchase response".to_string()
            )))?;

        self.delivery(&package_name_str, Some(actual_version_code), &download_token).await
    }

    /// Performs a "delivery" request to obtain direct download links.
    async fn delivery<S: Into<String>>(
        &self,
        pkg_name: S,
        version_code: Option<i32>,
        download_token: S,
    ) -> Result<DownloadInfo, GpapiError> {
        let package_name_str: String = pkg_name.into();
        let download_token_str: String = download_token.into();

        if self.auth_subtoken.is_none() {
             return Err(GpapiError::new(GpapiErrorKind::Str("User not logged in. Call login() first.".to_string())));
        }

        let actual_version_code = version_code.ok_or_else(|| GpapiError::new(GpapiErrorKind::Str(
            "Version code is required for delivery request".to_string()
        )))?;

        let delivery_response_wrapper = {
            let version_code_string = actual_version_code.to_string();
            let mut request_params = HashMap::new();
            request_params.insert("doc", package_name_str.as_str());
            request_params.insert("vc", &version_code_string);
            request_params.insert("dtok", &download_token_str);
            request_params.insert("ot", "1");
            self.execute_request_v2("delivery", Some(request_params), None, HeaderMap::new())
                .await
                .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?
        };

        let app_delivery_data = delivery_response_wrapper.payload
            .and_then(|p| p.delivery_response)
            .and_then(|dr| dr.app_delivery_data)
            .ok_or_else(|| GpapiError::new(GpapiErrorKind::Str(
                "AppDeliveryData missing from delivery response".to_string()
            )))?;

        let mut splits = Vec::new();
        for app_split_proto in app_delivery_data.split {
            splits.push((app_split_proto.name, app_split_proto.download_url));
        }

        let mut additional_files = Vec::new();
        for additional_file_proto in app_delivery_data.additional_file {
            if let Some(file_type) = additional_file_proto.file_type {
                if let Some(vc_val) = additional_file_proto.version_code {
                    let main_or_patch_prefix = match file_type {
                        0 => "main",
                        _ => "patch",
                    };
                    let obb_filename = format!("{}.{}.{}.obb", main_or_patch_prefix, vc_val, package_name_str);
                    additional_files.push((Some(obb_filename), additional_file_proto.download_url));
                }
            }
        }

        Ok((app_delivery_data.download_url, splits, additional_files))
    }

    /// Fetches detailed information for a specific app package.
    pub async fn details<S: Into<String>>(
        &self,
        pkg_name: S,
    ) -> Result<Option<DetailsResponse>, GpapiError> {
        let package_name_str: String = pkg_name.into();
        let mut request_params = HashMap::new();
        request_params.insert("doc", package_name_str.as_str());
        let response_wrapper = self
            .execute_request_v2("details", Some(request_params), None, HeaderMap::new())
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        Ok(response_wrapper.payload.and_then(|p| p.details_response))
    }

    /// Fetches the latest version code for a given package name.
    async fn get_latest_version_for_pkg_name(&self, pkg_name: &str) -> Result<i32, GpapiError> {
        let details_opt = self.details(pkg_name).await?;

        details_opt
            .and_then(|details_response| details_response.doc_v2)
            .and_then(|doc_v2| doc_v2.details)
            .and_then(|document_details| document_details.app_details)
            .and_then(|app_details| app_details.version_code)
            .ok_or_else(|| GpapiError::new(GpapiErrorKind::Str(format!(
                "Could not find version code for package: {}", pkg_name
            ))))
    }

    /// Fetches detailed information for multiple app packages.
    pub async fn bulk_details(
        &self,
        pkg_names: &[&str],
    ) -> Result<Option<BulkDetailsResponse>, GpapiError> {
        let mut bulk_request_proto = BulkDetailsRequest::default();
        bulk_request_proto.docid = pkg_names.iter().map(|&s| String::from(s)).collect();
        bulk_request_proto.include_child_docs = Some(false);

        let mut request_bytes = Vec::new();
        bulk_request_proto.encode(&mut request_bytes)
            .map_err(GpapiError::from)?;

        let response_wrapper = self
            .execute_request_v2("bulkDetails", None, Some(&request_bytes), HeaderMap::new())
            .await
            .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?;

        Ok(response_wrapper.payload.and_then(|p| p.bulk_details_response))
    }

    /// Obtains a service-specific authentication subtoken.
    async fn get_auth_subtoken(
        &mut self,
        email: &str,
        b64_encrypted_login: &str,
    ) -> Result<(), Box<dyn StdError>> {
        let mut auth_request_params = build_login_request(email, b64_encrypted_login);
        auth_request_params.params.insert(String::from("service"), String::from("androidmarket"));
        auth_request_params.params.insert(String::from("app"), String::from("com.android.vending"));

        let auth_response_map = self.authenticate_helper(&auth_request_params).await?;

        if let Some(master_token) = auth_response_map.get("token") {
            self.auth_subtoken = self.get_second_round_token(master_token, auth_request_params).await?;
        } else if let Some(auth_token) = auth_response_map.get("auth") {
            self.auth_subtoken = Some(auth_token.to_string());
        }

        if self.auth_subtoken.is_none() {
            return Err(Box::new(GpapiError::new(GpapiErrorKind::Str(
                "Failed to get master token or auth subtoken in get_auth_subtoken".to_string()
            ))));
        }
        Ok(())
    }

    /// Second stage of subtoken acquisition.
    async fn get_second_round_token(
        &self,
        master_token: &str,
        mut auth_request_params: LoginRequest,
    ) -> Result<Option<String>, Box<dyn StdError>> {
        if let Some(gsf_id_val) = self.gsf_id {
            auth_request_params.params.insert(String::from("androidId"), format!("{:x}", gsf_id_val));
        }
        auth_request_params.params.insert(String::from("Token"), String::from(master_token));
        auth_request_params.params.insert(String::from("check_email"), String::from("1"));
        auth_request_params.params.insert(String::from("token_request_options"), String::from("CAA4AQ=="));
        auth_request_params.params.insert(String::from("system_partition"), String::from("1"));
        auth_request_params.params.insert(String::from("_opt_is_called_from_account_manager"), String::from("1"));

        auth_request_params.params.remove("Email");
        auth_request_params.params.remove("EncryptedPasswd");

        let response_map = self.authenticate_helper(&auth_request_params).await?;
        Ok(response_map.get("auth").map(String::from))
    }

    /// Performs initial authentication.
    async fn authenticate(
        &self,
        email: &str,
        b64_encrypted_login_payload: &str,
    ) -> Result<HashMap<String, String>, Box<dyn StdError>> {
        let auth_request = build_login_request(email, b64_encrypted_login_payload);
        self.authenticate_helper(&auth_request).await
    }

    /// Low-level authentication request helper.
    async fn authenticate_helper(
        &self,
        auth_params: &LoginRequest,
    ) -> Result<HashMap<String, String>, Box<dyn StdError>> {
        let form_body_string = auth_params.form_post();

        let mut http_request = HyperRequest::builder()
            .method(Method::POST)
            .uri(format!("{}/{}", consts::defaults::DEFAULT_BASE_URL, "auth"))
            .body(Body::from(form_body_string))?;

        let headers = http_request.headers_mut();
        headers.insert(hyper::header::USER_AGENT, HyperHeaderValue::from_str(&consts::defaults::DEFAULT_AUTH_USER_AGENT)?);
        headers.insert(hyper::header::CONTENT_TYPE, HyperHeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"));

        if let Some(current_gsf_id) = &self.gsf_id {
            headers.insert(HyperHeaderName::from_static("device"), HyperHeaderValue::from_str(&format!("{:x}", current_gsf_id))?);
            if let Some(app_param) = auth_params.params.get("app") {
                 headers.insert(HyperHeaderName::from_static("app"), HyperHeaderValue::from_str(app_param)?);
            } else {
                 headers.insert(HyperHeaderName::from_static("app"), HyperHeaderValue::from_static("com.android.vending"));
            }
        }

        let http_response = self.hyper_client.request(http_request).await?;

        let response_body_bytes = hyper::body::to_bytes(http_response.into_body()).await?;
        let body_vec = response_body_bytes.to_vec();
        let response_string = std::str::from_utf8(&body_vec)?;
        let parsed_response_map = parse_form_reply(response_string);

        Ok(parsed_response_map)
    }

    /// Central helper for making version 2 API requests.
    async fn execute_request_v2(
        &self,
        endpoint: &str,
        query_params: Option<HashMap<&str, &str>>,
        request_body_bytes: Option<&[u8]>,
        additional_headers: HeaderMap,
    ) -> Result<ResponseWrapper, Box<dyn StdError>> {
        let response_bytes = self
            .execute_request_helper(endpoint, query_params, request_body_bytes, additional_headers, true)
            .await?;
        ResponseWrapper::decode(&mut Cursor::new(response_bytes))
            .map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)
    }

    /// Executes a specialized check-in request.
    async fn execute_checkin_request(
        &self,
        request_body_bytes: &[u8],
    ) -> Result<AndroidCheckinResponse, Box<dyn StdError>> {
        let response_bytes = self
            .execute_request_helper("checkin", None, Some(request_body_bytes), HeaderMap::new(), false)
            .await?;
        AndroidCheckinResponse::decode(&mut Cursor::new(response_bytes))
            .map_err(|e| Box::new(GpapiError::from(e)) as Box<dyn StdError>)
    }

    /// Core HTTP request execution logic.
    async fn execute_request_helper(
        &self,
        endpoint: &str,
        query_params_map: Option<HashMap<&str, &str>>,
        request_body_proto_bytes: Option<&[u8]>,
        mut headers_map: HeaderMap,
        use_fdfe_prefix: bool,
    ) -> Result<Bytes, Box<dyn StdError>> {
        let base_api_url = consts::defaults::DEFAULT_BASE_URL;
        let full_url_string = if use_fdfe_prefix {
            format!("{}/fdfe/{}", base_api_url, endpoint)
        } else {
            format!("{}/{}", base_api_url, endpoint)
        };

        let mut request_url = Url::parse(&full_url_string)?;

        if let Some(ref params_map_ref) = query_params_map {
            let mut query_pairs = request_url.query_pairs_mut();
            for (key, val) in params_map_ref {
                query_pairs.append_pair(key, val);
            }
        }

        let build_config = BuildConfiguration::default();
        headers_map.insert(reqwest::header::ACCEPT_LANGUAGE, HeaderValue::from_str(&self.locale.replace("_", "-"))?);
        headers_map.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(&build_config.user_agent())?);
        headers_map.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_static("application/x-protobuf"));
        headers_map.insert("X-DFE-Encoded-Targets", HeaderValue::from_static(consts::defaults::DEFAULT_DFE_TARGETS));
        headers_map.insert("X-DFE-Client-Id", HeaderValue::from_static("am-android-google"));

        let mcc_mnc = ANDROID_CHECKINS
            .get(&self.device_codename)
            .and_then(|raw_checkin_bytes| AndroidCheckinProto::decode(&mut Cursor::new(raw_checkin_bytes.clone())).ok())
            .and_then(|checkin_proto| checkin_proto.cell_operator)
            .unwrap_or_else(|| "310260".to_string());
        headers_map.insert("X-DFE-MCCMCN", HeaderValue::from_str(&mcc_mnc)?);

        headers_map.insert("X-DFE-Network-Type", HeaderValue::from_static("4"));
        headers_map.insert("X-DFE-Content-Filters", HeaderValue::from_static(""));
        headers_map.insert("X-DFE-Request-Params", HeaderValue::from_static("timeoutMs=4000"));

        if let Some(current_gsf_id) = &self.gsf_id {
            headers_map.insert("X-DFE-Device-Id", HeaderValue::from_str(&format!("{:x}", current_gsf_id))?);
        }
        if let Some(current_auth_subtoken) = &self.auth_subtoken {
            headers_map.insert(reqwest::header::AUTHORIZATION, HeaderValue::from_str(&format!("GoogleLogin auth={}", current_auth_subtoken))?);
        }
        if let Some(current_device_config_token) = &self.device_config_token {
            headers_map.insert("X-DFE-Device-Config-Token", HeaderValue::from_str(current_device_config_token)?);
        }
        if let Some(current_device_checkin_token) = &self.device_checkin_consistency_token {
            headers_map.insert("X-DFE-Device-Checkin-Consistency-Token", HeaderValue::from_str(current_device_checkin_token)?);
        }
        if let Some(current_dfe_cookie) = &self.dfe_cookie {
            headers_map.insert("X-DFE-Cookie", HeaderValue::from_str(current_dfe_cookie)?);
        }

        let http_response = if endpoint == "purchase" && query_params_map.is_some() {
            self.client
                .post(request_url)
                .headers(headers_map)
                .form(&query_params_map.expect("query_params_map checked by is_some"))
                .send()
                .await?
        } else {
            if let Some(body_bytes) = request_body_proto_bytes {
                self.client
                    .post(request_url)
                    .headers(headers_map)
                    .body(body_bytes.to_owned())
                    .send()
                    .await?
            } else {
                self.client.get(request_url).headers(headers_map).send().await?
            }
        };

        Ok(http_response.bytes().await?)
    }
}

/// RSA public key components.
#[derive(Debug)]
struct PubKey {
    pub modulus: Vec<u8>,
    pub exp: Vec<u8>,
}

/// Parses form-urlencoded string into a HashMap. Keys are lowercased.
fn parse_form_reply(form_data_str: &str) -> HashMap<String, String> {
    let mut response_map = HashMap::new();
    let lines: Vec<&str> = form_data_str.split_terminator('\n').collect();
    for line_str_ref in lines.iter() {
        let kv_pair: Vec<&str> = line_str_ref.split_terminator('=').collect();
        if kv_pair.is_empty() { continue; }
        let key = String::from(kv_pair[0]).to_lowercase();
        let value = if kv_pair.len() > 1 { String::from(kv_pair[1..].join("=")) } else { String::from("") };
        response_map.insert(key, value);
    }
    response_map
}

/// Encrypts login email and password using Google's RSA public key.
/// Output: `0x00 | SHA1(pubkey)[0..4] | RSA_encrypt(email\x00password)`
fn encrypt_login(email: &str, password: &str) -> Result<Vec<u8>, GpapiError> {
    let raw_public_key = b64_general_purpose::STANDARD.decode(consts::GOOGLE_PUB_KEY_B64)
        .map_err(GpapiError::from)?;

    let public_key_components = extract_pubkey(&raw_public_key)
        .map_err(|e| GpapiError::new(GpapiErrorKind::Other(e)))?
        .ok_or_else(|| GpapiError::new(GpapiErrorKind::Str("Failed to extract public key components".to_string())))?;

    let rsa_key = build_openssl_rsa(&public_key_components);

    let login_data_string = format!("{login}\x00{password}", login = email, password = password);
    if login_data_string.as_bytes().len() >= (rsa_key.size() as usize - 41) {
        return Err(GpapiError::new(GpapiErrorKind::EncryptLogin));
    }

    let mut encrypted_output_buffer = vec![0u8; rsa_key.size() as usize];
    let padding_scheme = openssl::rsa::Padding::PKCS1_OAEP;

    rsa_key.public_encrypt(login_data_string.as_bytes(), &mut encrypted_output_buffer, padding_scheme)
        .map_err(GpapiError::from)?;

    let public_key_sha1_hash = openssl::sha::sha1(&raw_public_key);
    let mut result_payload:Vec<u8> = Vec::with_capacity(1 + 4 + rsa_key.size() as usize);
    result_payload.push(0x00);
    result_payload.extend_from_slice(&public_key_sha1_hash[0..4]);
    result_payload.extend_from_slice(&encrypted_output_buffer);

    Ok(result_payload)
}

/// Constructs OpenSSL `Rsa<Public>` from `PubKey` components.
fn build_openssl_rsa(public_key_components: &PubKey) -> Rsa<Public> {
    use openssl::bn::BigNum;
    let modulus_bn = BigNum::from_slice(&public_key_components.modulus)
        .expect("Failed to create BigNum from modulus for RSA key");
    let exponent_bn = BigNum::from_slice(&public_key_components.exp)
        .expect("Failed to create BigNum from exponent for RSA key");

    Rsa::from_public_components(modulus_bn, exponent_bn)
        .expect("Failed to build RSA key from public components")
}

/// Extracts RSA public key modulus and exponent from raw bytes.
fn extract_pubkey(raw_key_bytes: &[u8]) -> Result<Option<PubKey>, Box<dyn StdError>> {
    use byteorder::{NetworkEndian, ReadBytesExt};
    use std::io::Read;
    let mut cursor = Cursor::new(raw_key_bytes);

    if raw_key_bytes.len() < 4 { return Ok(None); }
    let modulus_len = cursor.read_u32::<NetworkEndian>()? as usize;
    if modulus_len == 0 || cursor.position() as usize + modulus_len > raw_key_bytes.len() { return Ok(None); }
    let mut modulus_bytes = vec![0u8; modulus_len];
    cursor.read_exact(&mut modulus_bytes)?;

    if cursor.position() as usize + 4 > raw_key_bytes.len() { return Ok(None); }
    let exponent_len = cursor.read_u32::<NetworkEndian>()? as usize;
    if exponent_len == 0 || cursor.position() as usize + exponent_len > raw_key_bytes.len() { return Ok(None); }
    let mut exponent_bytes = vec![0u8; exponent_len];
    cursor.read_exact(&mut exponent_bytes)?;

    Ok(Some(PubKey { modulus: modulus_bytes, exp: exponent_bytes }))
}

/// Parameters for a login request.
#[derive(Debug, Clone)]
struct LoginRequest {
    params: HashMap<String, String>,
    build_config: Option<BuildConfiguration>,
}

impl LoginRequest {
    /// Converts params to URL-encoded string.
    pub fn form_post(&self) -> String {
        self.params
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join("&")
    }
}

/// Device and app version properties for User-Agent.
#[derive(Debug, Clone)]
struct BuildConfiguration {
    pub finsky_agent: String,
    pub finsky_version: String,
    pub api: String,
    pub version_code: String,
    pub sdk: String,
    pub device: String,
    pub hardware: String,
    pub product: String,
    pub platform_version_release: String,
    pub model: String,
    pub build_id: String,
    pub is_wide_screen: String,
    pub supported_abis: String,
}

impl BuildConfiguration {
    /// Constructs User-Agent string.
    pub fn user_agent(&self) -> String {
        format!("{}/{} (api={},versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen={},supportedAbis={})", 
          self.finsky_agent, self.finsky_version, self.api, self.version_code, self.sdk,
          self.device, self.hardware, self.product,
          self.platform_version_release, self.model, self.build_id,
          self.is_wide_screen, self.supported_abis
        )
    }
}

/// Default `BuildConfiguration`.
impl Default for BuildConfiguration {
    fn default() -> BuildConfiguration {
        use consts::defaults::api_user_agent::{
            DEFAULT_API, DEFAULT_BUILD_ID, DEFAULT_DEVICE, DEFAULT_HARDWARE,
            DEFAULT_IS_WIDE_SCREEN, DEFAULT_MODEL, DEFAULT_PLATFORM_VERSION_RELEASE,
            DEFAULT_PRODUCT, DEFAULT_SDK, DEFAULT_SUPPORTED_ABIS, DEFAULT_VERSION_CODE,
        };
        use consts::defaults::{DEFAULT_FINSKY_AGENT, DEFAULT_FINSKY_VERSION};

        BuildConfiguration {
            finsky_agent: DEFAULT_FINSKY_AGENT.to_string(),
            finsky_version: DEFAULT_FINSKY_VERSION.to_string(),
            api: DEFAULT_API.to_string(),
            version_code: DEFAULT_VERSION_CODE.to_string(),
            sdk: DEFAULT_SDK.to_string(),
            device: DEFAULT_DEVICE.to_string(),
            hardware: DEFAULT_HARDWARE.to_string(),
            product: DEFAULT_PRODUCT.to_string(),
            platform_version_release: DEFAULT_PLATFORM_VERSION_RELEASE.to_string(),
            model: DEFAULT_MODEL.to_string(),
            build_id: DEFAULT_BUILD_ID.to_string(),
            is_wide_screen: DEFAULT_IS_WIDE_SCREEN.to_string(),
            supported_abis: DEFAULT_SUPPORTED_ABIS.to_string(),
        }
    }
}

/// Default `LoginRequest` parameters.
impl Default for LoginRequest {
    fn default() -> Self {
        let mut params = HashMap::new();
        params.insert(String::from("Email"), String::from(""));
        params.insert(String::from("EncryptedPasswd"), String::from(""));
        params.insert(String::from("add_account"), String::from("1"));
        params.insert(String::from("accountType"), String::from(consts::defaults::DEFAULT_ACCOUNT_TYPE));
        params.insert(String::from("google_play_services_version"), String::from(consts::defaults::DEFAULT_GOOGLE_PLAY_SERVICES_VERSION));
        params.insert(String::from("has_permission"), String::from("1"));
        params.insert(String::from("source"), String::from("android"));
        params.insert(String::from("device_country"), String::from(consts::defaults::DEFAULT_DEVICE_COUNTRY));
        params.insert(String::from("operatorCountry"), String::from(consts::defaults::DEFAULT_COUNTRY_CODE));
        params.insert(String::from("lang"), String::from(consts::defaults::DEFAULT_LANGUAGE));
        params.insert(String::from("client_sig"), String::from(consts::defaults::DEFAULT_CLIENT_SIG));
        params.insert(String::from("callerSig"), String::from(consts::defaults::DEFAULT_CALLER_SIG));
        params.insert(String::from("droidguard_results"), String::from(consts::defaults::DEFAULT_DROIDGUARD_RESULTS));
        params.insert(String::from("service"), String::from(consts::defaults::DEFAULT_SERVICE));
        params.insert(String::from("callerPkg"), String::from(consts::defaults::DEFAULT_ANDROID_VENDING));
        LoginRequest { params, build_config: None }
    }
}

/// Constructs `LoginRequest` with credentials.
fn build_login_request(email: &str, b64_encrypted_login_payload: &str) -> LoginRequest {
    let mut login_request_params = LoginRequest::default();
    login_request_params.build_config = Some(BuildConfiguration::default());
    login_request_params.params.insert(String::from("Email"), String::from(email));
    login_request_params.params.insert(String::from("EncryptedPasswd"), String::from(b64_encrypted_login_payload));
    login_request_params
}

#[cfg(test)]
mod tests {
    use super::*; // Imports Gpapi, GpapiError, GpapiErrorKind, etc.
    // Ensure HashMap is in scope for tests if not already by super::*
    use std::collections::HashMap;

    /// Tests the output properties of the `encrypt_login` function.
    /// It checks the prefix, overall length, and Base64 encoding characteristics.
    /// Note: This test does not decrypt; it verifies structural properties of the output.
    #[test]
    fn test_login_encryption_output_properties() { // Renamed from 'login'
        let enc_result = encrypt_login("foo", "bar");
        assert!(enc_result.is_ok(), "encrypt_login failed: {:?}", enc_result.err());
        let enc = enc_result.unwrap();

        assert_eq!(enc[0], 0x00, "Encrypted payload should start with 0x00 byte prefix.");
        // Length check based on 1024-bit RSA key (128 bytes) + 1 byte prefix + 4 bytes hash
        assert_eq!(enc.len(), 133, "Encrypted payload length. Expected 133 for 1024-bit RSA + prefix/hash.");

        // The following assertions are more specific and might be brittle if crypto details change.
        // They were part of the original tests.
        let base64_std_encoded = b64_general_purpose::STANDARD.encode(&enc);
        assert!(base64_std_encoded.starts_with("AFcb4K"), "Base64 standard encoded output prefix mismatch. Value: {}", base64_std_encoded);
        assert_eq!(base64_std_encoded.len(), 180, "Base64 standard encoded output length mismatch.");

        let base64_url_safe_encoded = b64_general_purpose::URL_SAFE_NO_PAD.encode(&enc);
        assert!(!base64_url_safe_encoded.contains("/"), "URL Safe Base64 encoded output should not contain '/'.");
        assert!(!base64_url_safe_encoded.contains("+"), "URL Safe Base64 encoded output should not contain '+'.");
        assert!(!base64_url_safe_encoded.ends_with("="), "URL Safe Base64 (NoPad) encoded output should not have padding '='.");
    }

    /// Tests basic functionality of `parse_form_reply`: two key-value pairs and key lowercasing.
    #[test]
    fn test_parse_form_reply_basic() { // Renamed from 'parse_form'
        let form_reply_str = "FOO=BAR\nbaz=qux"; // Renamed
        let mut expected_map = HashMap::new(); // Renamed
        expected_map.insert("baz".to_string(), "qux".to_string());
        expected_map.insert("foo".to_string(), "BAR".to_string());
        let parsed_map = parse_form_reply(form_reply_str); // Renamed
        assert_eq!(parsed_map, expected_map, "Basic form parsing with key lowercasing failed.");
    }

    /// Tests extended cases for `parse_form_reply` function, including empty input,
    /// multiple pairs, uppercase keys, values with '=', and handling of newlines.
    #[test]
    fn test_parse_form_reply_extended_cases() { // Renamed from 'test_parse_form_extended'
        // Case a: Empty input string
        let form_reply_empty = "";
        let expected_reply_empty: HashMap<String, String> = HashMap::new();
        assert_eq!(parse_form_reply(form_reply_empty), expected_reply_empty, "Test Case a: Empty input string should result in an empty map.");

        // Case b: Input with multiple key-value pairs
        let form_reply_multiple = "Key1=Value1\nKey2=Value2\nKey3=Value3";
        let mut expected_reply_multiple = HashMap::new();
        expected_reply_multiple.insert("key1".to_string(), "Value1".to_string());
        expected_reply_multiple.insert("key2".to_string(), "Value2".to_string());
        expected_reply_multiple.insert("key3".to_string(), "Value3".to_string());
        assert_eq!(parse_form_reply(form_reply_multiple), expected_reply_multiple, "Test Case b: Parsing multiple key-value pairs failed.");

        // Case c: Input with keys that need lowercasing (explicitly re-tested for clarity)
        let form_reply_uppercase = "UPPERCASEKEY=Value";
        let mut expected_reply_uppercase = HashMap::new();
        expected_reply_uppercase.insert("uppercasekey".to_string(), "Value".to_string());
        assert_eq!(parse_form_reply(form_reply_uppercase), expected_reply_uppercase, "Test Case c: Lowercasing of an uppercase key failed.");

        // Case d: Input with values containing the '=' character
        let form_reply_equals_in_value = "KeyWithEquals=Value1=StillValue1\nAnotherKey=Value2"; // Renamed
        let mut expected_reply_equals_in_value = HashMap::new(); // Renamed
        expected_reply_equals_in_value.insert("keywithequals".to_string(), "Value1=StillValue1".to_string());
        expected_reply_equals_in_value.insert("anotherkey".to_string(), "Value2".to_string());
        assert_eq!(parse_form_reply(form_reply_equals_in_value), expected_reply_equals_in_value, "Test Case d: Parsing value with '=' character failed.");

        // Case e: Input with leading/trailing newlines.
        // Based on `split_terminator` behavior: leading/trailing empty strings caused by separators at start/end are ignored.
        let form_reply_newlines = "\nKey1=Value1\nKey2=Value2\n";
        let mut expected_reply_newlines = HashMap::new();
        expected_reply_newlines.insert("key1".to_string(), "Value1".to_string());
        expected_reply_newlines.insert("key2".to_string(), "Value2".to_string());
        assert_eq!(parse_form_reply(form_reply_newlines), expected_reply_newlines, "Test Case e: Handling of leading/trailing newlines failed.");

        // Case f: Input with empty lines between key-value pairs.
        // `split_terminator` will produce an empty string for the line between `\n\n`.
        // The robust `parse_form_reply` converts this to `"":""`.
        // However, previous refactoring established that `split_terminator` filters these out.
        // Re-confirming this behavior from current code: `split_terminator` does not yield empty strings from `\n\n` if that means the segment is empty.
        // `Key1=Value1\n\nKey2=Value2` -> `["Key1=Value1", "Key2=Value2"]` if empty strings are fully filtered.
        // If `parse_form_reply` is `for line in lines.iter() { if line.is_empty() { continue } ... }` this is true.
        // The current `parse_form_reply` does *not* have `if line.is_empty() {continue}`.
        // However, the observed behavior from test failures suggests that `split_terminator('\n')`
        // on "Key1=Value1\n\nKey2=Value2" results in `["Key1=Value1", "Key2=Value2"]`,
        // meaning the empty string between consecutive newlines is filtered out by `split_terminator`.
        let form_reply_empty_lines = "Key1=Value1\n\nKey2=Value2";
        let mut expected_reply_empty_lines = HashMap::new();
        expected_reply_empty_lines.insert("key1".to_string(), "Value1".to_string());
        // No longer expecting {"": ""} based on consistent behavior of split_terminator filtering all empty segments.
        expected_reply_empty_lines.insert("key2".to_string(), "Value2".to_string());
        assert_eq!(parse_form_reply(form_reply_empty_lines), expected_reply_empty_lines, "Test Case f: Handling of empty lines between key-value pairs failed.");
    }

    /// Tests for functions and logic within the `gpapi` submodule/context.
    mod gpapi {
        use std::env;
        use super::Gpapi;
        use googleplay_protobuf::BulkDetailsRequest;

        /// Integration test for the Gpapi client login flow and basic API calls.
        /// This test is ignored by default as it requires valid GOOGLE_LOGIN and GOOGLE_PASSWORD
        /// environment variables and makes live network requests.
        #[tokio::test]
        #[ignore]
        async fn test_full_login_and_basic_api_calls_integration() { // Renamed
            match (env::var("GOOGLE_LOGIN"), env::var("GOOGLE_PASSWORD")) {
                (Ok(email), Ok(password)) => {
                    let mut api = Gpapi::new("en_US", "UTC", "hero2lte");
                    api.login(email, password).await.expect("API login failed during integration test.");

                    assert!(api.auth_subtoken.is_some(), "Auth subtoken should be present after successful login.");
                    assert!(api.device_config_token.is_some(), "Device config token should be present after successful login.");
                    assert!(api.device_checkin_consistency_token.is_some(), "Device checkin token should be present after successful login.");

                    // Verify with a simple, non-mutating API call.
                    let details_result = api.details("com.google.android.gm").await; // Using a common Google app
                    assert!(details_result.is_ok(), "Fetching app details failed: {:?}", details_result.err());
                    assert!(details_result.unwrap().is_some(), "Details response should not be None for a valid package like Gmail.");

                    let pkg_names_for_bulk = ["com.google.android.gm", "com.android.chrome"];
                    let bulk_details_result = api.bulk_details(&pkg_names_for_bulk).await;
                    assert!(bulk_details_result.is_ok(), "Fetching bulk details failed: {:?}", bulk_details_result.err());
                    assert!(bulk_details_result.unwrap().is_some(), "Bulk details response should not be None for valid packages.");
                }
                _ => panic!("Integration test `test_full_login_and_basic_api_calls_integration` requires GOOGLE_LOGIN and GOOGLE_PASSWORD environment variables."),
            }
        }

        /// Basic smoke test to ensure `BulkDetailsRequest` protobuf message can be instantiated.
        /// This primarily verifies that protobuf code generation is working.
        #[test]
        fn test_protobuf_bulkdetailsrequest_instantiation() { // Renamed
            let mut bulk_details_request = BulkDetailsRequest::default();
            bulk_details_request.docid = vec!["test.package.name".to_string()].into();
            bulk_details_request.include_child_docs = Some(true);
            assert_eq!(bulk_details_request.docid[0], "test.package.name", "Protobuf message field assignment failed.");
            assert_eq!(bulk_details_request.include_child_docs, Some(true), "Protobuf message field assignment for Option failed.");
        }
    }

    /// Tests the `encrypt_login` function with valid, typical inputs.
    /// Verifies the structure and properties of the encrypted output.
    #[test]
    fn test_encrypt_login_with_valid_input() { // Renamed
        let login = "test_user";
        let password = "test_password";
        let result = encrypt_login(login, password).expect("encrypt_login failed with valid input");

        assert_eq!(result[0], 0x00, "Encrypted output should start with a 0x00 byte.");

        let pub_key_raw = b64_general_purpose::STANDARD.decode(consts::GOOGLE_PUB_KEY_B64)
            .expect("Failed to decode Google public key for test verification.");
        let pub_key_hash = openssl::sha::sha1(&pub_key_raw);
        assert_eq!(&result[1..5], &pub_key_hash[0..4], "Bytes 1-4 of encrypted output should match first 4 bytes of public key SHA1 hash.");

        // Expected length: 1 (0x00 prefix) + 4 (hash prefix) + 128 (1024-bit RSA encrypted data) = 133 bytes.
        assert_eq!(result.len(), 133, "Encrypted output length is incorrect, expected 133 bytes for 1024-bit RSA key.");
    }

    /// Tests that `encrypt_login` returns an `EncryptLogin` error when the combined
    /// input (login + password + null separator) is too long for RSA encryption.
    #[test]
    fn test_encrypt_login_error_for_long_input() { // Renamed
        // Max data length for 1024-bit RSA with PKCS#1 OAEP padding (SHA1 hash) is typically key_size_in_bytes - 42.
        // 128 (key size) - 42 = 86 bytes.
        // The function itself checks against `rsa_key.size() as usize - 41`, which is 87 for a 128-byte key.
        // So, input data of length 87 or more should fail.
        let login = "a".repeat(43);
        let long_password = "b".repeat(44); // login (43) + null (1) + password (44) = 88 bytes.

        let result = encrypt_login(&login, &long_password);
        assert!(result.is_err(), "encrypt_login should return an error for input exceeding RSA capacity.");

        // Assert that the ErrorKind of the error is GpapiErrorKind::EncryptLogin.
        // Use the public `kind()` method instead of destructuring private fields.
        if let Err(err) = result {
            assert_eq!(*err.kind(), GpapiErrorKind::EncryptLogin, "Error kind should be EncryptLogin for oversized input.");
        } else {
            // This case should not be reached if the assert!(result.is_err()) above passed.
            // Adding it for completeness or if the first assert is removed.
            panic!("Expected an error for long input to encrypt_login, but got Ok.");
        }
    }

    /// Tests the `BuildConfiguration::user_agent()` method with default values.
    /// Verifies that the generated User-Agent string matches the expected format and content
    /// derived from constants.
    #[test]
    fn test_build_configuration_default_user_agent_string() { // Renamed
        let config = BuildConfiguration::default();
        let user_agent = config.user_agent();

        let expected_user_agent = format!(
            "{}/{} (api={},versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen={},supportedAbis={})",
            consts::defaults::DEFAULT_FINSKY_AGENT,
            consts::defaults::DEFAULT_FINSKY_VERSION,
            consts::defaults::api_user_agent::DEFAULT_API,
            consts::defaults::api_user_agent::DEFAULT_VERSION_CODE,
            consts::defaults::api_user_agent::DEFAULT_SDK,
            consts::defaults::api_user_agent::DEFAULT_DEVICE,
            consts::defaults::api_user_agent::DEFAULT_HARDWARE,
            consts::defaults::api_user_agent::DEFAULT_PRODUCT,
            consts::defaults::api_user_agent::DEFAULT_PLATFORM_VERSION_RELEASE,
            consts::defaults::api_user_agent::DEFAULT_MODEL,
            consts::defaults::api_user_agent::DEFAULT_BUILD_ID,
            consts::defaults::api_user_agent::DEFAULT_IS_WIDE_SCREEN,
            consts::defaults::api_user_agent::DEFAULT_SUPPORTED_ABIS
        );
        assert_eq!(user_agent, expected_user_agent, "Default User-Agent string does not match expected value.");
    }

    /// Tests the `BuildConfiguration::user_agent()` method with custom values.
    /// Verifies that the generated User-Agent string correctly incorporates all custom field values.
    #[test]
    fn test_build_configuration_custom_user_agent_string() { // Renamed
        let custom_config = BuildConfiguration { // Renamed
            finsky_agent: "CustomFinskyAgent".to_string(),
            finsky_version: "1.2.3-custom".to_string(),
            api: "X".to_string(),
            version_code: "1001".to_string(),
            sdk: "33".to_string(),
            device: "customDeviceX".to_string(),
            hardware: "customHardwareY".to_string(),
            product: "customProductZ".to_string(),
            platform_version_release: "13.0".to_string(),
            model: "CustomModel SXL".to_string(),
            build_id: "CUSTOM_BUILD_XYZ".to_string(),
            is_wide_screen: "1".to_string(),
            supported_abis: "x86_64,arm64-v8a".to_string(),
        };
        let user_agent = custom_config.user_agent();

        let expected_user_agent = format!(
            "{}/{} (api={},versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen={},supportedAbis={})",
            "CustomFinskyAgent", "1.2.3-custom", "X", "1001", "33", "customDeviceX", "customHardwareY",
            "customProductZ", "13.0", "CustomModel SXL", "CUSTOM_BUILD_XYZ", "1", "x86_64,arm64-v8a"
        );
        assert_eq!(user_agent, expected_user_agent, "Custom User-Agent string does not match expected value.");
    }
}

// Helper From impls
impl From<StdSystemTimeError> for GpapiError {
    fn from(err: StdSystemTimeError) -> Self {
        GpapiError::new(GpapiErrorKind::Other(Box::new(err)))
    }
}
impl From<ProstDecodeError> for GpapiError {
    fn from(err: ProstDecodeError) -> Self {
        GpapiError::new(GpapiErrorKind::Other(Box::new(err) as Box<dyn StdError>))
    }
}
impl From<ProstEncodeError> for GpapiError {
    fn from(err: ProstEncodeError) -> Self {
        GpapiError::new(GpapiErrorKind::Other(Box::new(err) as Box<dyn StdError>))
    }
}
impl From<OpenSslErrorStack> for GpapiError {
    fn from(err: OpenSslErrorStack) -> Self {
        GpapiError::new(GpapiErrorKind::Other(Box::new(err) as Box<dyn StdError>))
    }
}
impl From<base64::DecodeError> for GpapiError {
    fn from(err: base64::DecodeError) -> Self {
        GpapiError::new(GpapiErrorKind::Other(Box::new(err)))
    }
}
