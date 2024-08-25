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
}

impl Regex {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: Self::parse_regex(pattern),
        }
    }

    fn parse_regex(pattern: &str) -> Vec<PatternElement> {
        let mut patterns = Vec::new();
        let mut chars = pattern.chars();

        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(c) = chars.next() {
                        let el = match c {
                            'd' => PatternElement::Digit,
                            'w' => PatternElement::Alphanumeric,
                            _ => panic!("Invalid regex: {}", pattern),
                        };
                        patterns.push(el);
                    } else {
                        patterns.push(PatternElement::Literal(c));
                    }
                }
                c => patterns.push(PatternElement::Literal(c)),
            }
        }
        patterns
    }

    pub fn matches(&self, mut input: &str) -> bool {
        let mut patterns = self.pattern.iter();

        // First find the start of first pattern element.
        // This can be anywhere in the input and is thus special case.
        // All following pattern elements must directly follow the first one.
        // Thus if we set the input to an input after the first match
        // then the for loop below thus must match pattern at the start of input.

        if let Some(p) = patterns.next() {
            match p {
                PatternElement::Literal(c) => {
                    let Some(i) = input.find(*c) else {
                        return false;
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::Digit => {
                    let Some(i) = input.chars().position(|c| c.is_ascii_digit()) else {
                        return false;
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
                PatternElement::Alphanumeric => {
                    let Some(i) = input
                        .chars()
                        .position(|c| c.is_ascii_alphanumeric() || c == '_')
                    else {
                        return false;
                    };
                    input = input.get(i + 1..).unwrap_or_default();
                }
            }
        }

        for p in patterns {
            match p {
                PatternElement::Literal(c) => {
                    if !input.starts_with(*c) {
                        return false;
                    }
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::Digit => {
                    if let Some(c) = input.chars().next() {
                        if !c.is_numeric() {
                            return false;
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return false;
                    }
                }
                PatternElement::Alphanumeric => {
                    if let Some(c) = input.chars().next() {
                        if !(c.is_ascii_alphanumeric() || c == '_') {
                            return false;
                        }
                        input = input.get(1..).unwrap_or_default();
                    } else {
                        return false;
                    }
                }
            }
        }

        true
    }
}

#[derive(Debug)]
enum PatternElement {
    Literal(char),
    Digit,
    Alphanumeric,
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
}
