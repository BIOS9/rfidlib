#![allow(non_camel_case_types, unsafe_code)]

use core::{ffi::c_void, ptr};

use tapsmith_ffi::{
    tapsmith_abi_version, tapsmith_gallagher_credential_decode, TapsmithGallagherCredential,
    TAPSMITH_GALLAGHER_CREDENTIAL_LEN, TAPSMITH_STATUS_INVALID_CREDENTIAL,
    TAPSMITH_STATUS_INVALID_LENGTH, TAPSMITH_STATUS_NULL_POINTER,
};

type jint = i32;
type jsize = jint;
type jbyte = i8;
type jclass = *mut c_void;
type jbyteArray = *mut c_void;
type jintArray = *mut c_void;

const CREDENTIAL_LEN_JSIZE: jsize = 8;
const FIELD_COUNT_JSIZE: jsize = 4;

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
    get_object_class: *mut c_void,
    is_instance_of: *mut c_void,
    get_method_id: *mut c_void,
    call_object_method: *mut c_void,
    call_object_method_v: *mut c_void,
    call_object_method_a: *mut c_void,
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
    new_byte_array: *mut c_void,
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
    set_byte_array_region: *mut c_void,
    set_char_array_region: *mut c_void,
    set_short_array_region: *mut c_void,
    set_int_array_region:
        unsafe extern "system" fn(*mut JNIEnv, jintArray, jsize, jsize, *const jint),
}

type JNIEnv = *const JNINativeInterface;

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
    jint::try_from(tapsmith_abi_version()).unwrap_or(-1)
}

#[no_mangle]
/// Decodes an encoded Gallagher credential from a Java byte array.
///
/// # Safety
///
/// This function is called by the JVM through JNI. `env` must be a valid JNI
/// environment pointer, `data` must be a Java byte array, and `out_fields` must
/// be a Java int array with at least four elements.
pub unsafe extern "system" fn Java_bios9_tapsmith_rfid_TapSmithNative_decodeGallagherCredential(
    env: *mut JNIEnv,
    _class: jclass,
    data: jbyteArray,
    out_fields: jintArray,
) -> jint {
    if data.is_null() || out_fields.is_null() {
        return TAPSMITH_STATUS_NULL_POINTER;
    }

    let data_len = ((**env).get_array_length)(env, data);
    if usize::try_from(data_len).ok() != Some(TAPSMITH_GALLAGHER_CREDENTIAL_LEN) {
        return TAPSMITH_STATUS_INVALID_LENGTH;
    }

    let out_len = ((**env).get_array_length)(env, out_fields);
    if out_len < FIELD_COUNT_JSIZE {
        return TAPSMITH_STATUS_INVALID_LENGTH;
    }

    let mut raw = [0_i8; TAPSMITH_GALLAGHER_CREDENTIAL_LEN];
    ((**env).get_byte_array_region)(env, data, 0, CREDENTIAL_LEN_JSIZE, raw.as_mut_ptr());

    let bytes = raw.map(i8::cast_unsigned);
    let mut credential = TapsmithGallagherCredential {
        region_code: 0,
        facility_code: 0,
        card_number: 0,
        issue_level: 0,
    };
    let status = tapsmith_gallagher_credential_decode(
        bytes.as_ptr(),
        bytes.len(),
        ptr::addr_of_mut!(credential),
    );
    if status == 0 {
        let Ok(card_number) = jint::try_from(credential.card_number) else {
            return TAPSMITH_STATUS_INVALID_CREDENTIAL;
        };
        let fields = [
            jint::from(credential.region_code),
            jint::from(credential.facility_code),
            card_number,
            jint::from(credential.issue_level),
        ];
        ((**env).set_int_array_region)(env, out_fields, 0, FIELD_COUNT_JSIZE, fields.as_ptr());
    }

    status
}
