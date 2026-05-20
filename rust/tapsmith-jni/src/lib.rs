#![allow(non_camel_case_types, unsafe_code)]

use core::ffi::{c_char, c_void};

use tapsmith_core::{
    gallagher::desfire::{GallagherDesfireKeySource, GallagherDesfireReader},
    mifare::desfire::{
        error::Error as DesfireError,
        transport::{Frame, MAX_FRAME_SIZE},
        Desfire, Transport, WrappedFraming,
    },
};

type jint = i32;
type jsize = jint;
type jbyte = i8;
type jclass = *mut c_void;
type jobject = *mut c_void;
type jmethodID = *mut c_void;
type jbyteArray = *mut c_void;
type jintArray = *mut c_void;

const TAPSMITH_JNI_ABI_VERSION: jint = 1;
const STATUS_NULL_POINTER: jint = -1;
const STATUS_INVALID_LENGTH: jint = -2;
const STATUS_INVALID_CREDENTIAL: jint = -3;
const STATUS_TRANSPORT_ERROR: jint = -10;
const FIELD_COUNT: usize = 5;
const FIELD_COUNT_JSIZE: jsize = 5;
const MAX_GALLAGHER_CREDENTIALS: usize = 12;

#[repr(C)]
union JValue {
    z: u8,
    b: jbyte,
    c: u16,
    s: i16,
    i: jint,
    j: i64,
    f: f32,
    d: f64,
    l: jobject,
}

#[repr(C)]
pub struct JNINativeInterface {
    reserved0: *mut c_void,
    reserved1: *mut c_void,
    reserved2: *mut c_void,
    reserved3: *mut c_void,
    get_version: *mut c_void,
    define_class: *mut c_void,
    find_class: *mut c_void,
    from_reflected_method: *mut c_void,
    from_reflected_field: *mut c_void,
    to_reflected_method: *mut c_void,
    get_superclass: *mut c_void,
    is_assignable_from: *mut c_void,
    to_reflected_field: *mut c_void,
    throw: *mut c_void,
    throw_new: *mut c_void,
    exception_occurred: *mut c_void,
    exception_describe: *mut c_void,
    exception_clear: *mut c_void,
    fatal_error: *mut c_void,
    push_local_frame: *mut c_void,
    pop_local_frame: *mut c_void,
    new_global_ref: *mut c_void,
    delete_global_ref: *mut c_void,
    delete_local_ref: *mut c_void,
    is_same_object: *mut c_void,
    new_local_ref: *mut c_void,
    ensure_local_capacity: *mut c_void,
    alloc_object: *mut c_void,
    new_object: *mut c_void,
    new_object_v: *mut c_void,
    new_object_a: *mut c_void,
    get_object_class: unsafe extern "system" fn(*mut JNIEnv, jobject) -> jclass,
    is_instance_of: *mut c_void,
    get_method_id:
        unsafe extern "system" fn(*mut JNIEnv, jclass, *const c_char, *const c_char) -> jmethodID,
    call_object_method: *mut c_void,
    call_object_method_v: *mut c_void,
    call_object_method_a:
        unsafe extern "system" fn(*mut JNIEnv, jobject, jmethodID, *const JValue) -> jobject,
    call_boolean_method: *mut c_void,
    call_boolean_method_v: *mut c_void,
    call_boolean_method_a: *mut c_void,
    call_byte_method: *mut c_void,
    call_byte_method_v: *mut c_void,
    call_byte_method_a: *mut c_void,
    call_char_method: *mut c_void,
    call_char_method_v: *mut c_void,
    call_char_method_a: *mut c_void,
    call_short_method: *mut c_void,
    call_short_method_v: *mut c_void,
    call_short_method_a: *mut c_void,
    call_int_method: *mut c_void,
    call_int_method_v: *mut c_void,
    call_int_method_a: *mut c_void,
    call_long_method: *mut c_void,
    call_long_method_v: *mut c_void,
    call_long_method_a: *mut c_void,
    call_float_method: *mut c_void,
    call_float_method_v: *mut c_void,
    call_float_method_a: *mut c_void,
    call_double_method: *mut c_void,
    call_double_method_v: *mut c_void,
    call_double_method_a: *mut c_void,
    call_void_method: *mut c_void,
    call_void_method_v: *mut c_void,
    call_void_method_a: *mut c_void,
    call_nonvirtual_object_method: *mut c_void,
    call_nonvirtual_object_method_v: *mut c_void,
    call_nonvirtual_object_method_a: *mut c_void,
    call_nonvirtual_boolean_method: *mut c_void,
    call_nonvirtual_boolean_method_v: *mut c_void,
    call_nonvirtual_boolean_method_a: *mut c_void,
    call_nonvirtual_byte_method: *mut c_void,
    call_nonvirtual_byte_method_v: *mut c_void,
    call_nonvirtual_byte_method_a: *mut c_void,
    call_nonvirtual_char_method: *mut c_void,
    call_nonvirtual_char_method_v: *mut c_void,
    call_nonvirtual_char_method_a: *mut c_void,
    call_nonvirtual_short_method: *mut c_void,
    call_nonvirtual_short_method_v: *mut c_void,
    call_nonvirtual_short_method_a: *mut c_void,
    call_nonvirtual_int_method: *mut c_void,
    call_nonvirtual_int_method_v: *mut c_void,
    call_nonvirtual_int_method_a: *mut c_void,
    call_nonvirtual_long_method: *mut c_void,
    call_nonvirtual_long_method_v: *mut c_void,
    call_nonvirtual_long_method_a: *mut c_void,
    call_nonvirtual_float_method: *mut c_void,
    call_nonvirtual_float_method_v: *mut c_void,
    call_nonvirtual_float_method_a: *mut c_void,
    call_nonvirtual_double_method: *mut c_void,
    call_nonvirtual_double_method_v: *mut c_void,
    call_nonvirtual_double_method_a: *mut c_void,
    call_nonvirtual_void_method: *mut c_void,
    call_nonvirtual_void_method_v: *mut c_void,
    call_nonvirtual_void_method_a: *mut c_void,
    get_field_id: *mut c_void,
    get_object_field: *mut c_void,
    get_boolean_field: *mut c_void,
    get_byte_field: *mut c_void,
    get_char_field: *mut c_void,
    get_short_field: *mut c_void,
    get_int_field: *mut c_void,
    get_long_field: *mut c_void,
    get_float_field: *mut c_void,
    get_double_field: *mut c_void,
    set_object_field: *mut c_void,
    set_boolean_field: *mut c_void,
    set_byte_field: *mut c_void,
    set_char_field: *mut c_void,
    set_short_field: *mut c_void,
    set_int_field: *mut c_void,
    set_long_field: *mut c_void,
    set_float_field: *mut c_void,
    set_double_field: *mut c_void,
    get_static_method_id: *mut c_void,
    call_static_object_method: *mut c_void,
    call_static_object_method_v: *mut c_void,
    call_static_object_method_a: *mut c_void,
    call_static_boolean_method: *mut c_void,
    call_static_boolean_method_v: *mut c_void,
    call_static_boolean_method_a: *mut c_void,
    call_static_byte_method: *mut c_void,
    call_static_byte_method_v: *mut c_void,
    call_static_byte_method_a: *mut c_void,
    call_static_char_method: *mut c_void,
    call_static_char_method_v: *mut c_void,
    call_static_char_method_a: *mut c_void,
    call_static_short_method: *mut c_void,
    call_static_short_method_v: *mut c_void,
    call_static_short_method_a: *mut c_void,
    call_static_int_method: *mut c_void,
    call_static_int_method_v: *mut c_void,
    call_static_int_method_a: *mut c_void,
    call_static_long_method: *mut c_void,
    call_static_long_method_v: *mut c_void,
    call_static_long_method_a: *mut c_void,
    call_static_float_method: *mut c_void,
    call_static_float_method_v: *mut c_void,
    call_static_float_method_a: *mut c_void,
    call_static_double_method: *mut c_void,
    call_static_double_method_v: *mut c_void,
    call_static_double_method_a: *mut c_void,
    call_static_void_method: *mut c_void,
    call_static_void_method_v: *mut c_void,
    call_static_void_method_a: *mut c_void,
    get_static_field_id: *mut c_void,
    get_static_object_field: *mut c_void,
    get_static_boolean_field: *mut c_void,
    get_static_byte_field: *mut c_void,
    get_static_char_field: *mut c_void,
    get_static_short_field: *mut c_void,
    get_static_int_field: *mut c_void,
    get_static_long_field: *mut c_void,
    get_static_float_field: *mut c_void,
    get_static_double_field: *mut c_void,
    set_static_object_field: *mut c_void,
    set_static_boolean_field: *mut c_void,
    set_static_byte_field: *mut c_void,
    set_static_char_field: *mut c_void,
    set_static_short_field: *mut c_void,
    set_static_int_field: *mut c_void,
    set_static_long_field: *mut c_void,
    set_static_float_field: *mut c_void,
    set_static_double_field: *mut c_void,
    new_string: *mut c_void,
    get_string_length: *mut c_void,
    get_string_chars: *mut c_void,
    release_string_chars: *mut c_void,
    new_string_utf: *mut c_void,
    get_string_utf_length: *mut c_void,
    get_string_utf_chars: *mut c_void,
    release_string_utf_chars: *mut c_void,
    get_array_length: unsafe extern "system" fn(*mut JNIEnv, *mut c_void) -> jsize,
    new_object_array: *mut c_void,
    get_object_array_element: *mut c_void,
    set_object_array_element: *mut c_void,
    new_boolean_array: *mut c_void,
    new_byte_array: unsafe extern "system" fn(*mut JNIEnv, jsize) -> jbyteArray,
    new_char_array: *mut c_void,
    new_short_array: *mut c_void,
    new_int_array: *mut c_void,
    new_long_array: *mut c_void,
    new_float_array: *mut c_void,
    new_double_array: *mut c_void,
    get_boolean_array_elements: *mut c_void,
    get_byte_array_elements: *mut c_void,
    get_char_array_elements: *mut c_void,
    get_short_array_elements: *mut c_void,
    get_int_array_elements: *mut c_void,
    get_long_array_elements: *mut c_void,
    get_float_array_elements: *mut c_void,
    get_double_array_elements: *mut c_void,
    release_boolean_array_elements: *mut c_void,
    release_byte_array_elements: *mut c_void,
    release_char_array_elements: *mut c_void,
    release_short_array_elements: *mut c_void,
    release_int_array_elements: *mut c_void,
    release_long_array_elements: *mut c_void,
    release_float_array_elements: *mut c_void,
    release_double_array_elements: *mut c_void,
    get_boolean_array_region: *mut c_void,
    get_byte_array_region:
        unsafe extern "system" fn(*mut JNIEnv, jbyteArray, jsize, jsize, *mut jbyte),
    get_char_array_region: *mut c_void,
    get_short_array_region: *mut c_void,
    get_int_array_region: *mut c_void,
    get_long_array_region: *mut c_void,
    get_float_array_region: *mut c_void,
    get_double_array_region: *mut c_void,
    set_boolean_array_region: *mut c_void,
    set_byte_array_region:
        unsafe extern "system" fn(*mut JNIEnv, jbyteArray, jsize, jsize, *const jbyte),
    set_char_array_region: *mut c_void,
    set_short_array_region: *mut c_void,
    set_int_array_region:
        unsafe extern "system" fn(*mut JNIEnv, jintArray, jsize, jsize, *const jint),
}

type JNIEnv = *const JNINativeInterface;

struct AndroidIsoDepTransport {
    env: *mut JNIEnv,
    transceiver: jobject,
    transceive_method: jmethodID,
}

impl Transport for AndroidIsoDepTransport {
    fn transceive(&mut self, tx: &[u8], rx: &mut Frame) -> Result<(), DesfireError> {
        let tx_len = jsize::try_from(tx.len()).map_err(|_| DesfireError::CommandTooLong)?;
        let tx_array = unsafe { ((**self.env).new_byte_array)(self.env, tx_len) };
        if tx_array.is_null() {
            return Err(DesfireError::Transport);
        }

        let mut tx_bytes = [0_i8; MAX_FRAME_SIZE];
        for (out, byte) in tx_bytes.iter_mut().zip(tx) {
            *out = byte.cast_signed();
        }
        unsafe {
            ((**self.env).set_byte_array_region)(self.env, tx_array, 0, tx_len, tx_bytes.as_ptr());
        }

        let args = [JValue { l: tx_array }];
        let response = unsafe {
            ((**self.env).call_object_method_a)(
                self.env,
                self.transceiver,
                self.transceive_method,
                args.as_ptr(),
            )
        };
        if response.is_null() {
            return Err(DesfireError::Transport);
        }

        let response_len = unsafe { ((**self.env).get_array_length)(self.env, response) };
        let response_len = usize::try_from(response_len).map_err(|_| DesfireError::Transport)?;
        if response_len > MAX_FRAME_SIZE {
            return Err(DesfireError::ResponseTooLong);
        }

        let mut response_bytes = [0_i8; MAX_FRAME_SIZE];
        unsafe {
            ((**self.env).get_byte_array_region)(
                self.env,
                response,
                0,
                jsize::try_from(response_len).map_err(|_| DesfireError::Transport)?,
                response_bytes.as_mut_ptr(),
            );
        }

        rx.clear();
        for byte in response_bytes.iter().take(response_len) {
            rx.push(byte.cast_unsigned())
                .map_err(|_| DesfireError::ResponseTooLong)?;
        }
        Ok(())
    }
}

#[no_mangle]
/// Returns the `TapSmith` C ABI version exposed by the bundled native library.
///
/// # Safety
///
/// This function is called by the JVM through JNI. `env` and `_class` are
/// provided by the JVM and are not dereferenced.
pub unsafe extern "system" fn Java_bios9_tapsmith_rfid_TapSmithNative_abiVersion(
    _env: *mut JNIEnv,
    _class: jclass,
) -> jint {
    TAPSMITH_JNI_ABI_VERSION
}

#[no_mangle]
/// Reads Gallagher credentials found on a `DESFire` tag.
///
/// # Safety
///
/// This function is called by the JVM through JNI. `env` must be a valid JNI
/// environment pointer, `transceiver` must expose `transceive(byte[]): byte[]`,
/// and `out_fields` must be a Java int array whose length is a multiple of
/// five: region code, facility code, card number, issue level, application ID.
pub unsafe extern "system" fn Java_bios9_tapsmith_rfid_TapSmithNative_readGallagherDesfire(
    env: *mut JNIEnv,
    _class: jclass,
    transceiver: jobject,
    out_fields: jintArray,
) -> jint {
    if transceiver.is_null() || out_fields.is_null() {
        return STATUS_NULL_POINTER;
    }
    let out_len = ((**env).get_array_length)(env, out_fields);
    if out_len < FIELD_COUNT_JSIZE || out_len % FIELD_COUNT_JSIZE != 0 {
        return STATUS_INVALID_LENGTH;
    }
    let Ok(capacity) = usize::try_from(out_len / FIELD_COUNT_JSIZE) else {
        return STATUS_INVALID_LENGTH;
    };

    let transceiver_class = ((**env).get_object_class)(env, transceiver);
    if transceiver_class.is_null() {
        return STATUS_TRANSPORT_ERROR;
    }
    let transceive_method = ((**env).get_method_id)(
        env,
        transceiver_class,
        c"transceive".as_ptr(),
        c"([B)[B".as_ptr(),
    );
    if transceive_method.is_null() {
        return STATUS_TRANSPORT_ERROR;
    }

    let transport = AndroidIsoDepTransport {
        env,
        transceiver,
        transceive_method,
    };
    let mut desfire = Desfire::new(transport, WrappedFraming);
    let read = GallagherDesfireReader::read_from_desfire(
        &mut desfire,
        GallagherDesfireKeySource::DefaultSiteKey,
    );

    let Ok(gallagher) = read else {
        return STATUS_INVALID_CREDENTIAL;
    };
    if gallagher.credentials.is_empty() {
        return STATUS_INVALID_CREDENTIAL;
    }

    let mut fields = [0; MAX_GALLAGHER_CREDENTIALS * FIELD_COUNT];
    let mut count = 0_usize;
    for source in gallagher.credentials.iter().take(capacity) {
        let credential = source.credential;
        let Ok(card_number) = jint::try_from(credential.card_number) else {
            return STATUS_INVALID_CREDENTIAL;
        };
        let Ok(application_id) = jint::try_from(source.application_id.as_u32()) else {
            return STATUS_INVALID_CREDENTIAL;
        };
        let offset = count * FIELD_COUNT;
        fields[offset] = jint::from(credential.region_code);
        fields[offset + 1] = jint::from(credential.facility_code);
        fields[offset + 2] = card_number;
        fields[offset + 3] = jint::from(credential.issue_level);
        fields[offset + 4] = application_id;
        count += 1;
    }

    let Ok(write_len) = jsize::try_from(count * FIELD_COUNT) else {
        return STATUS_INVALID_LENGTH;
    };
    ((**env).set_int_array_region)(env, out_fields, 0, write_len, fields.as_ptr());

    let Ok(count) = jsize::try_from(count) else {
        return STATUS_INVALID_LENGTH;
    };
    count
}
