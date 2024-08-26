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
        } else {
            todo!("Empty pattern");
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
                '+' if !patterns.is_empty() => {
                    let last = patterns.remove(patterns.len() - 1);
                    patterns.push(PatternElement::OneOrMore(Box::new(last)));
                }
                '?' if !patterns.is_empty() => {
                    let last = patterns.remove(patterns.len() - 1);
                    patterns.push(PatternElement::ZeroOrOne(Box::new(last)));
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
            let Some((_, end)) = Self::find_match_anywhere(p, input) else {
                return (false, "");
            };

            input = input.get(end..).unwrap_or_default();
        } else {
            // empty pattern
            todo!("Empty pattern");
        }

        let input_after_first = input;
        for p in patterns {
            let Some(end) = Self::find_match_at_start(p, input) else {
                return (false, input_after_first);
            };
            input = input.get(end..).unwrap_or_default();
        }

        (true, input_after_first)
    }

    /// Finds the first match of pattern anywhere in the input and returns the start index and one past the end of match.
    ///
    /// Returns None if there is no match.
    fn find_match_anywhere(pattern: &PatternElement, input: &str) -> Option<(usize, usize)> {
        match pattern {
            PatternElement::StartAnchor => Some((0, 0)),
            PatternElement::Literal(c) => input.find(*c).map(|i| (i, i + 1)),
            PatternElement::Digit => input
                .chars()
                .position(|c| c.is_ascii_digit())
                .map(|i| (i, i + 1)),
            PatternElement::Alphanumeric => input
                .chars()
                .position(|c| c.is_ascii_alphanumeric() || c == '_')
                .map(|i| (i, i + 1)),
            PatternElement::PosCharGroup(chars) => input
                .chars()
                .position(|c| chars.contains(&c))
                .map(|i| (i, i + 1)),
            PatternElement::NegCharGroup(chars) => input
                .chars()
                .position(|c| !chars.contains(&c))
                .map(|i| (i, i + 1)),
            PatternElement::EndAnchor => {
                // not sure what should be done here
                unimplemented!("EndAnchor")
            }
            PatternElement::OneOrMore(p) => {
                let (start, mut end) = Self::find_match_anywhere(p, input)?;

                while let Some(next) = Self::find_match_at_start(p, &input[end..]) {
                    end += next;
                }

                Some((start, end))
            }
            PatternElement::ZeroOrOne(p) => {
                Self::find_match_anywhere(p, input).or(Some((0, 0)))
            }
        }
    }

    /// Matches the `pattern` at the start of `input` and returns the length of the match
    /// (or alternatively an index one past the match).
    ///
    /// Returns `None` if there is no match.
    fn find_match_at_start(pattern: &PatternElement, input: &str) -> Option<usize> {
        match pattern {
            PatternElement::StartAnchor => Some(0),
            PatternElement::Literal(c) if input.starts_with(*c) => Some(1),
            PatternElement::Literal(_) => None,
            PatternElement::Digit => {
                if let Some(c) = input.chars().next() {
                    if !c.is_numeric() {
                        return None;
                    }
                } else {
                    return None;
                }

                Some(1)
            }
            PatternElement::Alphanumeric => {
                if let Some(c) = input.chars().next() {
                    if !(c.is_ascii_alphanumeric() || c == '_') {
                        return None;
                    }
                } else {
                    return None;
                }

                Some(1)
            }
            PatternElement::PosCharGroup(chars) => {
                if let Some(c) = input.chars().next() {
                    if !chars.contains(&c) {
                        return None;
                    }
                } else {
                    return None;
                }

                Some(1)
            }
            PatternElement::NegCharGroup(chars) => {
                if let Some(c) = input.chars().next() {
                    if chars.contains(&c) {
                        return None;
                    }
                } else {
                    return None;
                }

                Some(1)
            }
            PatternElement::EndAnchor => {
                if input.chars().next().is_none() {
                    Some(0)
                } else {
                    None
                }
            }
            PatternElement::OneOrMore(p) => {
                let mut end = Self::find_match_at_start(p, input)?;

                while let Some(next) = Self::find_match_at_start(p, &input[end..]) {
                    end += next;
                }

                Some(end)
            }
            PatternElement::ZeroOrOne(p) => Self::find_match_at_start(p, input).or(Some(0)),
        }
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
    OneOrMore(Box<PatternElement>),
    ZeroOrOne(Box<PatternElement>),
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
        assert!(regex.matches("abcabcabc"));
    }

    #[test]
    fn test_at_start_end() {
        let regex = Regex::new(r"^abc$");
        dbg!(&regex);
        assert!(regex.matches("abc"));
        assert!(!regex.matches("abcd"));
        assert!(!regex.matches("abxxabc"));
    }

    #[test]
    fn test_one_or_more() {
        let regex = Regex::new(r"ca+ts$");
        dbg!(&regex);
        assert!(regex.matches("cats"));
        assert!(regex.matches("caats"));
        assert!(!regex.matches("cts"));

        let regex = Regex::new(r"ca+t\d+s$");
        dbg!(&regex);
        assert!(regex.matches("cat1s"));
        assert!(regex.matches("caat12354s"));
        assert!(!regex.matches("ct16513s"));
    }

    #[test]
    fn test_zero_or_one() {
        let regex = Regex::new(r"dogs?$");
        dbg!(&regex);
        assert!(regex.matches("dogs"));
        assert!(regex.matches("dog"));
        assert!(!regex.matches("dos"));
    }
}
