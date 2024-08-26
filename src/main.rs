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

    //dbg!(&pattern, &regex);

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
        let (pattern, anchor, _) = Self::parse_regex(pattern, false);
        Self { pattern, anchor }
    }

    fn parse_regex(pattern: &str, open_group: bool) -> (Vec<PatternElement>, Anchor, &str) {
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
                            c if c.is_ascii_digit() => {
                                let index = c.to_digit(10).unwrap() as usize;
                                PatternElement::BackRef(index)
                            }
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
                '(' if chars.as_str().contains(')') => {
                    let (group, _, remainder) = Self::parse_regex(&chars.as_str(), true);
                    chars = remainder.chars();

                    patterns.push(PatternElement::Group(group));
                }
                ')' if open_group => {
                    return (patterns, anchor, chars.as_str());
                }
                '+' if !patterns.is_empty() => {
                    let last = patterns.remove(patterns.len() - 1);
                    match last {
                        PatternElement::Str(mut s) => {
                            assert!(!s.is_empty());
                            let last_char = s.remove(s.len() - 1);
                            if !s.is_empty() {
                                patterns.push(PatternElement::Str(s));
                                patterns.push(PatternElement::OneOrMore(Box::new(
                                    PatternElement::Literal(last_char),
                                )));
                            }
                        }
                        _ => {
                            patterns.push(PatternElement::OneOrMore(Box::new(last)));
                        }
                    }
                }
                '?' if !patterns.is_empty() => {
                    let last = patterns.remove(patterns.len() - 1);
                    match last {
                        PatternElement::Str(mut s) => {
                            assert!(!s.is_empty());
                            let last_char = s.remove(s.len() - 1);
                            if !s.is_empty() {
                                patterns.push(PatternElement::Str(s));
                                patterns.push(PatternElement::ZeroOrOne(Box::new(
                                    PatternElement::Literal(last_char),
                                )));
                            }
                        }
                        _ => {
                            patterns.push(PatternElement::ZeroOrOne(Box::new(last)));
                        }
                    }
                }
                '.' => patterns.push(PatternElement::Wildcard),
                '|' => {
                    let lhs = std::mem::take(&mut patterns);
                    let (rhs, _, remainder) = Self::parse_regex(chars.as_str(), open_group);

                    patterns.push(PatternElement::Alternation(lhs, rhs));
                    return (patterns, anchor, remainder);
                }
                '$' if chars.as_str().is_empty() => patterns.push(PatternElement::EndAnchor),
                c if patterns.is_empty() => patterns.push(PatternElement::Literal(c)),
                c => match patterns.remove(patterns.len() - 1) {
                    PatternElement::Str(mut s) => {
                        s.push(c);
                        patterns.push(PatternElement::Str(s));
                    }
                    PatternElement::Literal(prev_c) => {
                        let mut s = String::with_capacity(2);
                        s.push(prev_c);
                        s.push(c);
                        patterns.push(PatternElement::Str(s));
                    }
                    prev => {
                        patterns.push(prev);
                        patterns.push(PatternElement::Literal(c));
                    }
                },
            }

            next_char = chars.next();
        }
        (patterns, anchor, chars.as_str())
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

        let mut captures = Vec::new();

        if let Some(p) = patterns.next() {
            let Some((_, end)) = Self::find_match_anywhere(p, input, &mut captures) else {
                return (false, "");
            };

            input = input.get(end..).unwrap_or_default();
        } else {
            // empty pattern
            todo!("Empty pattern");
        }

        let input_after_first = input;
        for p in patterns {
            let Some(end) = Self::find_match_at_start(p, input, &mut captures) else {
                return (false, input_after_first);
            };
            input = input.get(end..).unwrap_or_default();
        }

        dbg!(&captures);

        (true, input_after_first)
    }

    fn matches_anywhere(
        patterns: &[PatternElement],
        mut input: &str,
        captures: &mut Vec<String>,
    ) -> Option<(usize, usize)> {
        assert!(!matches!(patterns[0], PatternElement::StartAnchor));
        let mut patterns = patterns.iter();

        // First find the start of first pattern element.
        // This can be anywhere in the input and is thus special case.
        // All following pattern elements must directly follow the first one.
        // Thus if we set the input to an input after the first match
        // then the for loop below thus must match pattern at the start of input.
        let start;
        let end_first;
        if let Some(p) = patterns.next() {
            (start, end_first) = Self::find_match_anywhere(p, input, captures)?;
            if patterns.as_slice().is_empty() {
                return Some((start, end_first));
            }

            input = input.get(end_first..).unwrap_or_default();
        } else {
            // empty pattern
            todo!("Empty pattern");
        }

        Self::match_patterns_at_start(patterns.as_slice(), input, captures)
            .map(|end| (start, end_first + end))
    }

    /// Finds the first match of pattern anywhere in the input and returns the start index and one past the end of match.
    ///
    /// Returns None if there is no match.
    fn find_match_anywhere(
        pattern: &PatternElement,
        input: &str,
        captures: &mut Vec<String>,
    ) -> Option<(usize, usize)> {
        match pattern {
            PatternElement::StartAnchor => Some((0, 0)),
            PatternElement::Literal(c) => input.find(*c).map(|i| (i, i + 1)),
            PatternElement::Str(s) => input.find(s).map(|i| (i, i + s.len())),
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
                let (start, mut end) = Self::find_match_anywhere(p, input, captures)?;

                while let Some(next) = Self::find_match_at_start(p, &input[end..], captures) {
                    end += next;
                }

                Some((start, end))
            }
            PatternElement::ZeroOrOne(p) => {
                Self::find_match_anywhere(p, input, captures).or(Some((0, 0)))
            }
            PatternElement::Wildcard => Some((0, 1)),
            PatternElement::Alternation(first, alt) => {
                Self::matches_anywhere(first, input, captures)
                    .or_else(|| Self::matches_anywhere(alt, input, captures))
            }
            PatternElement::Group(group) => {
                let result = Self::matches_anywhere(group, input, captures);
                if let Some((start, end)) = result {
                    captures.push(input.get(start..end).unwrap_or_default().to_string());
                }

                result
            }
            PatternElement::BackRef(_) => unimplemented!("BackRef"),
        }
    }

    /// Matches the `pattern` at the start of `input` and returns the length of the match
    /// (or alternatively an index one past the match).
    ///
    /// Returns `None` if there is no match.
    fn find_match_at_start(
        pattern: &PatternElement,
        input: &str,
        captures: &mut Vec<String>,
    ) -> Option<usize> {
        match pattern {
            PatternElement::StartAnchor => Some(0),
            PatternElement::Literal(c) if input.starts_with(*c) => Some(1),
            PatternElement::Str(s) if input.starts_with(s) => Some(s.len()),
            PatternElement::Literal(_) | PatternElement::Str(_) => None,
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
                let mut end = Self::find_match_at_start(p, input, captures)?;

                while let Some(next) = Self::find_match_at_start(p, &input[end..], captures) {
                    end += next;
                }

                Some(end)
            }
            PatternElement::ZeroOrOne(p) => {
                Self::find_match_at_start(p, input, captures).or(Some(0))
            }
            PatternElement::Wildcard => Some(1),
            PatternElement::Alternation(first, alt) => {
                Self::match_patterns_at_start(first, input, captures)
                    .or_else(|| Self::match_patterns_at_start(alt, input, captures))
            }
            PatternElement::Group(patterns) => {
                let result = Self::match_patterns_at_start(patterns, input, captures);
                if let Some(end) = result {
                    captures.push(input.get(..end).unwrap_or_default().to_string());
                }

                result
            }
            PatternElement::BackRef(i) => {
                assert!(*i > 0);
                let capture = &captures[*i - 1];
                if input.starts_with(capture) {
                    Some(capture.len())
                } else {
                    None
                }
            }
        }
    }

    fn match_patterns_at_start(
        patterns: &[PatternElement],
        mut input: &str,
        captures: &mut Vec<String>,
    ) -> Option<usize> {
        let patterns = patterns.iter();
        let mut end = 0;

        for p in patterns {
            let next_end = Self::find_match_at_start(p, input, captures)?;
            input = input.get(next_end..).unwrap_or_default();
            end += next_end;
        }

        Some(end)
    }
}

#[derive(Debug)]
enum PatternElement {
    Literal(char),
    Str(String),
    Digit,
    Alphanumeric,
    PosCharGroup(Vec<char>),
    NegCharGroup(Vec<char>),
    StartAnchor,
    EndAnchor,
    OneOrMore(Box<PatternElement>),
    ZeroOrOne(Box<PatternElement>),
    Wildcard,
    Group(Vec<PatternElement>),
    Alternation(Vec<PatternElement>, Vec<PatternElement>),
    BackRef(usize),
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
        let regex = Regex::new(r"ca+ts");
        dbg!(&regex);
        assert!(regex.matches("cats"));
        assert!(regex.matches("caats"));
        assert!(!regex.matches("cts"));

        let regex = Regex::new(r"ca+t\d+s");
        dbg!(&regex);
        assert!(regex.matches("cat1s"));
        assert!(regex.matches("caat12354s"));
        assert!(!regex.matches("ct16513s"));
    }

    #[test]
    fn test_zero_or_one() {
        let regex = Regex::new(r"dogs?");
        dbg!(&regex);
        assert!(regex.matches("dogs"));
        assert!(regex.matches("dog"));
        assert!(!regex.matches("dos"));
    }

    #[test]
    fn test_wildcard() {
        let regex = Regex::new(r"d.g");
        dbg!(&regex);
        assert!(regex.matches("dogs"));
        assert!(regex.matches("dgg"));
        assert!(!regex.matches("dys"));
    }

    #[test]
    fn test_group() {
        let regex = Regex::new(r"a(bg)");
        dbg!(&regex);
        assert!(regex.matches("abg"));
        assert!(!regex.matches("dgg"));
        assert!(!regex.matches("dys"));
    }

    #[test]
    fn test_alteration_single() {
        let regex = Regex::new(r"a|b");
        dbg!(&regex);
        assert!(regex.matches("a"));
        assert!(regex.matches("b"));
        assert!(regex.matches("ag"));
        assert!(regex.matches("hbf"));
        assert!(!regex.matches("dys"));

        let regex = Regex::new(r"a|b|c");
        dbg!(&regex);
        assert!(regex.matches("a"));
        assert!(regex.matches("b"));
        assert!(regex.matches("c"));
        assert!(!regex.matches("dys"));
    }

    #[test]
    fn test_alteration_multi() {
        let regex = Regex::new(r"cat|dog");
        dbg!(&regex);
        assert!(regex.matches("cat"));
        assert!(regex.matches("dog"));
        assert!(!regex.matches("caog"));

        let regex = Regex::new(r"ae|br|ct");
        dbg!(&regex);
        assert!(regex.matches("ae"));
        assert!(regex.matches("br"));
        assert!(regex.matches("ct"));
        assert!(regex.matches("aebgctsf"));
    }

    #[test]
    fn test_alteration_w_groups() {
        let regex = Regex::new(r"a(fs|b)");
        dbg!(&regex);
        assert!(regex.matches("afs"));
        assert!(regex.matches("ab"));
        assert!(!regex.matches("a"));
        assert!(!regex.matches("fs"));
        assert!(!regex.matches("b"));
        assert!(!regex.matches("dys"));

        let regex = Regex::new(r"aa(bb|cc|dd)(ee|ff|gg)");
        dbg!(&regex);
        assert!(regex.matches("aaccee"));
        assert!(regex.matches("aaddgg"));
        assert!(!regex.matches("aaff"));
        assert!(!regex.matches("aaffgg"));
    }

    #[test]
    fn test_back_ref() {
        let regex = Regex::new(r"(cat) and \1");
        dbg!(&regex);
        assert!(regex.matches("cat and cat"));
        assert!(!regex.matches("cat and dog"));

        let regex = Regex::new(r"(\w+) and \1");
        dbg!(&regex);
        assert!(regex.matches("cat and cat"));
        assert!(regex.matches("dog and dog"));
        assert!(!regex.matches("cat and dog"));

        let regex = Regex::new(r"(cat) and (\1) and (\2)");
        dbg!(&regex);
        assert!(regex.matches("cat and cat and cat"));
        assert!(!regex.matches("cat and cat and dog"));

        let regex = Regex::new(r"(\d+) (\w+) squares and \1 \2 circles");
        dbg!(&regex);
        assert!(regex.matches("3 red squares and 3 red circles"));
        assert!(!regex.matches("3 red squares and 4 red circles"));
    }

    #[test]
    fn test_back_ref_issue() {
        let regex = Regex::new(r"(\w\w\w\w \d\d\d) is doing \1 times");
        dbg!(&regex);
        assert!(regex.matches("grep 101 is doing grep 101 times"));
    }

    #[test]
    fn test_nested_groups() {
        let regex = Regex::new(r"(a (b\w) \d)+");
        dbg!(&regex);
        assert!(regex.matches("a ba 1"));
    }
}
