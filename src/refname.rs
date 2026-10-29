//! Git's ref-name rules, as `git check-ref-format <refname>` applies them
//! without options (git-check-ref-format(1)).

/// Whether `git check-ref-format` accepts `name`.
pub fn is_valid(name: &str) -> bool {
    // A single `@` is reserved for HEAD; at least two components are needed
    // without `--allow-onelevel`.
    if name == "@" || !name.contains('/') || name.ends_with('.') {
        return false;
    }
    name.split('/').all(is_valid_component)
}

fn is_valid_component(component: &str) -> bool {
    if component.is_empty() || component.starts_with('.') || component.ends_with(".lock") {
        return false;
    }
    let mut previous = 0_u8;
    for byte in component.bytes() {
        let forbidden = byte.is_ascii_control()
            || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            || (previous == b'.' && byte == b'.')
            || (previous == b'@' && byte == b'{');
        if forbidden {
            return false;
        }
        previous = byte;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::is_valid;
    use crate::gitcmd;

    const CASES: &[&str] = &[
        "refs/heads/main",
        "refs/heads/feature/x",
        "refs/tags/v1.0.0",
        "refs/heads/@",
        "refs/heads/a@b",
        "refs/heads/a{b",
        "refs/heads/@}",
        "refs/heads/a.b",
        "refs/heads/a-b",
        "refs/heads/-a",
        "refs/heads/HEAD",
        "refs/heads/ünïcödé",
        "refs/heads/a,b;c'd\"e",
        "refs/heads/a+b=c",
        "refs/heads/x.lockx",
        "refs/heads/lock",
        "refs/heads/a_.lock_",
        "@",
        "main",
        "",
        "/",
        "refs/heads/",
        "/refs/heads/main",
        "refs//heads/main",
        "refs/heads//main",
        "refs/heads/main/",
        "refs/heads/main.",
        "refs/heads/main..x",
        "refs/heads/..",
        "refs/heads/.",
        "refs/heads/.hidden",
        "refs/heads/a/.b",
        "refs/heads/main.lock",
        "refs/heads/main.lock/x",
        "refs/heads/.lock",
        "refs/heads/a@{b",
        "refs/heads/@{",
        "refs/heads/a b",
        "refs/heads/a~b",
        "refs/heads/a^b",
        "refs/heads/a:b",
        "refs/heads/a?b",
        "refs/heads/a*b",
        "refs/heads/*",
        "refs/heads/a[b",
        "refs/heads/a]b",
        "refs/heads/a\\b",
        "refs/heads/a\tb",
        "refs/heads/a\nb",
        "refs/heads/a\u{1}b",
        "refs/heads/a\u{7f}b",
        "refs/heads/a\u{80}b",
        "refs/heads/a.",
        "refs/heads/a./b",
        "refs/heads/a/b.",
    ];

    fn git_accepts(name: &str) -> bool {
        gitcmd::without_repository()
            .args(["check-ref-format", name])
            .output()
            .expect("run git check-ref-format")
            .status
            .success()
    }

    #[test]
    fn ref_name_rules_match_git_check_ref_format() {
        let mut accepted = 0;
        for name in CASES {
            let expected = git_accepts(name);
            assert_eq!(is_valid(name), expected, "{name:?}");
            accepted += usize::from(expected);
        }
        assert!(accepted > 5 && accepted < CASES.len() - 20);
    }
}
