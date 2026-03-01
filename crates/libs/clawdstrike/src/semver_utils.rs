/// Parse a strict `major.minor.patch` semantic version where all components are
/// unsigned decimal integers.
pub(crate) fn parse_strict_semver(value: &str) -> Option<[u32; 3]> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some([major, minor, patch])
}

pub(crate) fn is_strict_semver(value: &str) -> bool {
    parse_strict_semver(value).is_some()
}
