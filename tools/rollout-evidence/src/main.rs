//! Offline receipt consistency inspection, never execution certification.
use std::collections::BTreeSet;
use std::io::Read;

const REPOSITORY: &str = "ores-truffle-oreslang/oreslang-cli";
const CASES: &str = include_str!("../cases.tsv");
const LIMIT: u64 = 1024 * 1024;
const HEADER: &str = "repository\tsuite\tbackend\tphase\toutcome\tcommit\ttree\tcorpus_sha256\trun_id\tjob_id\tsteps\ttests\texit_code\tartifact_sha256";

fn digest(s: &str, size: usize) -> bool {
    s.len() == size
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}

fn positive(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with('0')
        && s.parse::<u64>().is_ok_and(|n| n > 0)
}

fn manifest(text: &str) -> Result<BTreeSet<(String, String, String)>, String> {
    let mut result = BTreeSet::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let c: Vec<_> = line.split('\t').collect();
        if c.len() != 3 || c.iter().any(|s| s.is_empty() || s.trim() != *s) {
            return Err("malformed acceptance manifest".into());
        }
        if !["execution", "rejection", "host", "model"].contains(&c[2]) {
            return Err("unknown manifest phase".into());
        }
        if !result.insert((c[0].into(), c[1].into(), c[2].into())) {
            return Err("duplicate acceptance case".into());
        }
    }
    if result.is_empty() {
        return Err("empty acceptance manifest".into());
    }
    Ok(result)
}

fn inspect(
    text: &str,
    cases: &str,
    repository: &str,
    commit: &str,
    tree: &str,
    corpus: &str,
) -> Result<usize, String> {
    if !digest(commit, 40) || !digest(tree, 40) || !digest(corpus, 64) {
        return Err("expected pins must be nonzero lowercase full digests".into());
    }
    if text.len() as u64 > LIMIT || !text.is_ascii() || text.contains('\r') {
        return Err("receipt must be bounded canonical ASCII/LF TSV".into());
    }
    let expected = manifest(cases)?;
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("missing or incompatible receipt header".into());
    }
    let mut seen = BTreeSet::new();
    for (i, line) in lines.enumerate() {
        let c: Vec<_> = line.split('\t').collect();
        let invalid = || format!("invalid receipt row {}", i + 2);
        if c.len() != 14 || c.iter().any(|s| s.is_empty() || s.trim() != *s) {
            return Err(invalid());
        }
        let key = (c[1].to_owned(), c[2].to_owned(), c[3].to_owned());
        if !expected.contains(&key) || !seen.insert(key) {
            return Err(format!("unknown or duplicate case at row {}", i + 2));
        }
        if c[0] != repository || c[4] != "pass" || c[5] != commit || c[6] != tree {
            return Err(invalid());
        }
        if c[7] != corpus || c[12] != "0" || !digest(c[13], 64) {
            return Err(invalid());
        }
        if !c[8..12].iter().all(|s| positive(s)) {
            return Err(format!(
                "missing executed-run/test metadata at row {}",
                i + 2
            ));
        }
    }
    if seen != expected {
        return Err("missing required acceptance cases".into());
    }
    Ok(seen.len())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--cases"] {
        print!("{CASES}");
        return Ok(());
    }
    if args.len() != 4 {
        return Err(
            "usage: ores-rollout-evidence RECEIPT.tsv COMMIT TREE CORPUS_SHA256; or --cases".into(),
        );
    }
    let file = std::fs::File::open(&args[0]).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("receipt exceeds 1 MiB".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let count = inspect(text, CASES, REPOSITORY, &args[1], &args[2], &args[3])?;
    println!("CONSISTENT_UNAUTHENTICATED_RECEIPT cases={count}; requires independent run/artifact verification");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("REJECTED: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> (String, String, String) {
        ("1".repeat(40), "2".repeat(40), "3".repeat(64))
    }
    fn receipt(cases: &str) -> String {
        let (commit, tree, corpus) = pins();
        let mut rows = vec![HEADER.to_owned()];
        for (suite, backend, phase) in manifest(cases).unwrap() {
            rows.push(format!("{REPOSITORY}\t{suite}\t{backend}\t{phase}\tpass\t{commit}\t{tree}\t{corpus}\t1\t2\t3\t4\t0\t{}", "4".repeat(64)));
        }
        rows.join("\n") + "\n"
    }
    fn check(text: &str, cases: &str) -> Result<usize, String> {
        let (commit, tree, corpus) = pins();
        inspect(text, cases, REPOSITORY, &commit, &tree, &corpus)
    }
    #[test]
    fn complete_local_profile_is_consistent_only() {
        assert_eq!(
            check(&receipt(CASES), CASES).unwrap(),
            manifest(CASES).unwrap().len()
        );
    }
    #[test]
    fn order_does_not_change_coverage() {
        let input = receipt(CASES);
        let mut rows: Vec<_> = input.lines().skip(1).collect();
        rows.reverse();
        assert!(check(&format!("{HEADER}\n{}\n", rows.join("\n")), CASES).is_ok());
    }
    #[test]
    fn malformed_or_empty_manifest_fails() {
        for cases in [
            "",
            "a\tb",
            "a\tb\tparity",
            "a\tb\thost\na\tb\thost",
            "a\t b\thost",
            "\n",
        ] {
            assert!(manifest(cases).is_err(), "{cases:?}");
        }
    }
    #[test]
    fn each_field_fails_closed() {
        let cases = "sample\tjava\texecution\n";
        let valid = receipt(cases);
        let original: Vec<_> = valid.lines().nth(1).unwrap().split('\t').collect();
        for index in 0..14 {
            for bad in ["", "unknown", " pass ", "0", "-1", "18446744073709551616"] {
                if original[index] == bad {
                    continue;
                }
                let mut fields = original.clone();
                fields[index] = bad;
                assert!(
                    check(&format!("{HEADER}\n{}\n", fields.join("\t")), cases).is_err(),
                    "field={index} value={bad:?}"
                );
            }
        }
    }
    #[test]
    fn status_is_not_promoted() {
        let cases = "sample\tjava\texecution\n";
        for status in [
            "NOT_EXECUTED",
            "skipped",
            "cancelled",
            "queued",
            "fail",
            "intentional_capability_reject",
            "model_pass",
        ] {
            assert!(check(
                &receipt(cases).replace("\tpass\t", &format!("\t{status}\t")),
                cases
            )
            .is_err());
        }
    }
    #[test]
    fn rejection_host_and_model_cannot_replace_execution() {
        let cases = "sample\tjava\texecution\n";
        for phase in ["rejection", "host", "model"] {
            assert!(check(
                &receipt(cases).replace("\texecution\t", &format!("\t{phase}\t")),
                cases
            )
            .is_err());
        }
    }
    #[test]
    fn pins_are_exact() {
        let cases = "sample\tjava\texecution\n";
        let text = receipt(cases);
        for (old, new) in [
            ("1".repeat(40), "5".repeat(40)),
            ("2".repeat(40), "6".repeat(40)),
            ("3".repeat(64), "7".repeat(64)),
        ] {
            assert!(check(&text.replace(&old, &new), cases).is_err());
        }
        for invalid in ["main", "1", &"0".repeat(40), &"A".repeat(40)] {
            let (_, tree, corpus) = pins();
            assert!(inspect(&text, cases, REPOSITORY, invalid, &tree, &corpus).is_err());
        }
    }
    #[test]
    fn missing_duplicate_extra_and_truncated_rows_fail() {
        let valid = receipt(CASES);
        let first = valid.lines().nth(1).unwrap();
        for text in [
            format!("{valid}{first}\n"),
            format!("{HEADER}\n"),
            valid.replacen(first, "", 1),
            format!("{valid}extra\n"),
        ] {
            assert!(check(&text, CASES).is_err());
        }
    }
    #[test]
    fn invalid_encoding_and_bounds_fail() {
        let valid = receipt(CASES);
        for text in [
            valid.replace('\n', "\r\n"),
            valid.replace("pass", "páss"),
            valid.replace("pass", "pa\0ss"),
            "x".repeat(LIMIT as usize + 1),
        ] {
            assert!(check(&text, CASES).is_err());
        }
    }
    #[test]
    fn header_and_column_count_are_strict() {
        let cases = "sample\tjava\texecution\n";
        let valid = receipt(cases);
        for text in [
            valid.replacen("repository", "repo", 1),
            valid.replace("\tpass\t", "\tpass\textra\t"),
            valid.replace("\tpass\t", "\t"),
            format!("{valid}\n"),
        ] {
            assert!(check(&text, cases).is_err());
        }
    }
}
