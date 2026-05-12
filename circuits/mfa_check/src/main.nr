// audit-core: MFA policy check
// Proves: MFA was used AND auth method is not plain password
// Private inputs keep raw auth details off-chain
//
// auth_method encoding: UNKNOWN=0, FIDO2=1, TOTP=2, PASSWORD=3

fn main(
    mfa_flag: bool,     // private: true if MFA used
    auth_method: u8,    // private: encoded auth method
) -> pub bool {
    let not_password = auth_method != 3;
    let not_unknown = auth_method != 0;
    let result = mfa_flag & not_password & not_unknown;
    assert(result);
    result
}
