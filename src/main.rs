use std::env;
use std::io;
use std::process;

// Usage: echo <input_text> | your_program.sh -E <pattern>
fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    if env::args().nth(1).unwrap() != "-E" {
        println!("Expected first argument to be '-E'");
        process::exit(1);
    }

    let pattern = env::args().nth(2).unwrap();
    let mut input_line = String::new();

    io::stdin().read_line(&mut input_line).unwrap();

    let regex = Regex::new(&pattern);

    dbg!(&pattern, &regex);

    // Uncomment this block to pass the first stage
    if regex.matches(&input_line) {
        process::exit(0)
    } else {
        process::exit(1)
    }
}

#[derive(Debug)]
struct Regex {
    pattern: Vec<PatternElement>,
    anchor: Anchor,
}

#[derive(Debug)]
enum Anchor {
    None,
    Start,
}

impl Regex {
    pub fn new(pattern: &str) -> Self {
        let (pattern, anchor) = Self::parse_regex(pattern);
        Self { pattern, anchor }
    }

    fn parse_regex(pattern: &str) -> (Vec<PatternElement>, Anchor) {
        let mut patterns = Vec::new();
        let mut chars = pattern.chars();
        let mut anchor = Anchor::None;

        let mut next_char = chars.next();
        if let Some(c) = next_char {
            if c == '^' {
                anchor = Anchor::Start;
                patterns.push(PatternElement::StartAnchor);
                next_char = chars.next();
            }
        }

        while let Some(c) = next_char {
            match c {
                '\\' => {
                    if let Some(c) = chars.next() {
                        let el = match c {
                            'd' => PatternElement::Digit,
                            'w' => PatternElement::Alphanumeric,
                            c => {
                                patterns.push(PatternElement::Literal('\\'));
                                PatternElement::Literal(c)
                            }
                        };
                        patterns.push(el);
                    } else {
                        patterns.push(PatternElement::Literal(c));
                    }
                }
                // look ahead to see if this character group closes
                '[' if chars.as_str().contains(']') => {
                    let mut group_chars = Vec::new();
                    let mut is_neg = false;
                    let mut next_char = chars.next();
                    if let Some(c) = next_char {
                        if c == '^' {
                            is_neg = true;
                            next_char = chars.next();
                        }
                    }
                    while let Some(c) = next_char {
                        match c {
                            ']' => break,
                            c => group_chars.push(c),
                        }

                        next_char = chars.next();
                    }

                    if is_neg {
                        patterns.push(PatternElement::NegCharGroup(group_chars));
                    } else {
                        patterns.push(PatternElement::PosCharGroup(group_chars));
                    }
                }
                '$' if chars.as_str().is_empty() => patterns.push(PatternElement::EndAnchor),
                c => patterns.push(PatternElement::Literal(c)),
            }

            next_char = chars.next();
        }
        (patterns, anchor)
    }

    pub fn matches(&self, mut input: &str) -> bool {
        match self.anchor {
            Anchor::None => {
                let mut result = false;
                while !result && !input.is_empty() {
                    (result, input) = self.matches_core(input);
                }

                result
            }
            Anchor::Start => self.matches_core(input).0,
        }
    }

    /// Returns (success, remaining input)
    ///
    /// The remaining input is the input after the first match so that we could
    /// later retry matching from that point.
    fn matches_core<'a>(&self, mut input: &'a str) -> (bool, &'a str) {
        let mut patterns = self.pattern.iter();

        // First find the start of first pattern element.
        // This can be anywhere in the input and is thus special case.
        // All following pattern elements must directly follow the first one.
        // Thus if we set the input to an input after the first match
        // then the for loop below thus must match pattern at the start of input.

        if let Some(p) = patterns.next() {
            match p {
                PatternElement::StartAnchor => {}
                PatternElement::Literal(c) => {
                    let Some(i) = input.find(*c) else {
                        return (false, "");
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::Digit => {
                    let Some(i) = input.chars().position(|c| c.is_ascii_digit()) else {
                        return (false, "");
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::Alphanumeric => {
                    let Some(i) = input
                        .chars()
                        .position(|c| c.is_ascii_alphanumeric() || c == '_')
                    else {
                        return (false, "");
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::PosCharGroup(chars) => {
                    let Some(i) = input.chars().position(|c| chars.contains(&c)) else {
                        return (false, "");
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::NegCharGroup(chars) => {
                    let Some(i) = input.chars().position(|c| !chars.contains(&c)) else {
                        return (false, "");
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::EndAnchor => {
                    // not sure what should be done here
                    unimplemented!("EndAnchor")
                }
            }
        }

        let input_after_first = input;
        for p in patterns {
            match p {
                PatternElement::StartAnchor => unreachable!("StartAnchor"),
                PatternElement::Literal(c) => {
                    if !input.starts_with(*c) {
                        return (false, input_after_first);
                    }
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::Digit => {
                    if let Some(c) = input.chars().next() {
                        if !c.is_numeric() {
                            return (false, input_after_first);
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return (false, "");
                    }
                }
                PatternElement::Alphanumeric => {
                    if let Some(c) = input.chars().next() {
                        if !(c.is_ascii_alphanumeric() || c == '_') {
                            return (false, input_after_first);
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return (false, "");
                    }
                }
                PatternElement::PosCharGroup(chars) => {
                    if let Some(c) = input.chars().next() {
                        if !chars.contains(&c) {
                            return (false, input_after_first);
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return (false, "");
                    }
                }
                PatternElement::NegCharGroup(chars) => {
                    if let Some(c) = input.chars().next() {
                        if chars.contains(&c) {
                            return (false, input_after_first);
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return (false, "");
                    }
                }
                PatternElement::EndAnchor => {
                    if input.chars().next().is_none() {
                        return (true, "");
                    } else {
                        return (false, input_after_first);
                    }
                }
            }
        }

        (true, input_after_first)
    }
}

#[derive(Debug)]
enum PatternElement {
    Literal(char),
    Digit,
    Alphanumeric,
    PosCharGroup(Vec<char>),
    NegCharGroup(Vec<char>),
    StartAnchor,
    EndAnchor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_char() {
        let regex = Regex::new("a");
        assert!(regex.matches("a"));
        assert!(regex.matches("apple"));
        assert!(!regex.matches("b"));
        assert!(!regex.matches("bhsrt"));

        let regex = Regex::new("[");
        assert!(!regex.matches("a"));
        assert!(regex.matches("app[le"));
    }

    #[test]
    fn test_digit() {
        let regex = Regex::new(r"\d");
        dbg!(&regex);
        assert!(regex.matches("1"));
        assert!(regex.matches("apple2"));
        assert!(!regex.matches("b"));
        assert!(!regex.matches("bhsrt"));
    }

    #[test]
    fn test_char_digit() {
        let regex = Regex::new(r"a\d");
        assert!(regex.matches("a1"));
        assert!(!regex.matches("apple2"));
        assert!(regex.matches("ba3"));
        assert!(!regex.matches("bhsrt"));

        let regex = Regex::new(r"\d apple\d\dyu");
        assert!(regex.matches("5 apple16yu"));
        assert!(!regex.matches("5 appe16yu"));
    }

    #[test]
    fn test_alphanumeric() {
        let regex = Regex::new(r"\w");
        dbg!(&regex);
        assert!(regex.matches("1"));
        assert!(regex.matches("apple2"));
        assert!(regex.matches("b"));
        assert!(regex.matches("bh_srt"));
        assert!(!regex.matches("$!"));
    }

    #[test]
    fn test_pos_char_group() {
        let regex = Regex::new(r"[abc]");
        dbg!(&regex);
        assert!(!regex.matches("1"));
        assert!(regex.matches("apple2"));
        assert!(regex.matches("b"));
        assert!(regex.matches("bh_srt"));
        assert!(!regex.matches("$!"));
    }

    #[test]
    fn test_neg_char_group() {
        let regex = Regex::new(r"[^abc]");
        dbg!(&regex);
        assert!(regex.matches("1"));
        assert!(regex.matches("apple2"));
        assert!(!regex.matches("b"));
        assert!(regex.matches("bh_srt"));
        assert!(regex.matches("$!"));
    }

    #[test]
    fn test_at_start() {
        let regex = Regex::new(r"^abc");
        dbg!(&regex);
        assert!(regex.matches("abcd"));
        assert!(!regex.matches("gabcd"));
    }

    #[test]
    fn test_partial_match() {
        let regex = Regex::new(r"abc");
        dbg!(&regex);
        assert!(regex.matches("abcd"));
        assert!(regex.matches("abxxabcd"));
        let regex = Regex::new(r"\d\da");
        dbg!(&regex);
        assert!(regex.matches("1a12a"));
        assert!(!regex.matches("1a2a3a"));
    }

    #[test]
    fn test_at_end() {
        let regex = Regex::new(r"abc$");
        dbg!(&regex);
        assert!(regex.matches("abc"));
        assert!(!regex.matches("abcd"));
        assert!(regex.matches("abxxabc"));
    }

    #[test]
    fn test_at_start_end() {
        let regex = Regex::new(r"^abc$");
        dbg!(&regex);
        assert!(regex.matches("abc"));
        assert!(!regex.matches("abcd"));
        assert!(!regex.matches("abxxabc"));
    }
}
