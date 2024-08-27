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
                    let (group, _, remainder) = Self::parse_regex(chars.as_str(), true);
                    chars = remainder.chars();

                    patterns.push(PatternElement::GroupStart);
                    patterns.extend(group);
                    patterns.push(PatternElement::GroupEnd);
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
                                patterns.push(PatternElement::Quantifier(
                                    Box::new(PatternElement::Literal(last_char)),
                                    1,
                                    None,
                                ));
                            }
                        }
                        _ => {
                            patterns.push(PatternElement::Quantifier(Box::new(last), 1, None));
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
                                patterns.push(PatternElement::Quantifier(
                                    Box::new(PatternElement::Literal(last_char)),
                                    0,
                                    Some(1),
                                ));
                            }
                        }
                        _ => {
                            patterns.push(PatternElement::Quantifier(Box::new(last), 0, Some(1)));
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

    pub fn matcher(&self) -> Matcher<'_> {
        Matcher::new(&self.pattern)
    }

    pub fn matches(&self, input: &str) -> bool {
        let matcher = self.matcher();

        match self.anchor {
            Anchor::None => matcher.matches(input),
            Anchor::Start => matcher.matches_at_start(input, input).is_success(),
        }
    }
}

#[derive(Debug)]
struct Matcher<'a> {
    patterns: &'a [PatternElement],
    group_id: usize,
    open_groups: Vec<(usize, usize)>,
    captures: Vec<&'a str>,
}

enum MatchResult<'a> {
    Success(usize, MatcherState<'a>),
    Fail(MatcherState<'a>),
}

impl<'a> MatchResult<'a> {
    /// Returns `true` if the match result is [`Success`].
    ///
    /// [`Success`]: MatchResult::Success
    #[must_use]
    fn is_success(&self) -> bool {
        matches!(self, Self::Success(..))
    }

    /// Returns `true` if the match result is [`Fail`].
    ///
    /// [`Fail`]: MatchResult::Fail
    #[must_use]
    fn is_fail(&self) -> bool {
        matches!(self, Self::Fail(..))
    }
}

#[derive(Debug)]
struct MatcherState<'a> {
    group_id: usize,
    open_groups: Vec<(usize, usize)>,
    captures: Vec<&'a str>,
}

impl<'a> MatcherState<'a> {
    fn new(group_id: usize, open_groups: Vec<(usize, usize)>, captures: Vec<&'a str>) -> Self {
        Self {
            group_id,
            open_groups,
            captures,
        }
    }
}

impl<'a> Matcher<'a> {
    fn new(main_patterns: &'a [PatternElement]) -> Self {
        Self {
            patterns: main_patterns,
            group_id: 0,
            open_groups: Vec::new(),
            captures: Vec::new(),
        }
    }

    fn new_from_middle(
        main_patterns: &'a [PatternElement],
        group_id: usize,
        open_groups: Vec<(usize, usize)>,
        captures: Vec<&'a str>,
    ) -> Self {
        Self {
            patterns: main_patterns,
            group_id,
            open_groups,
            captures,
        }
    }

    fn matches(self, input: &'a str) -> bool {
        for i in 0..input.len() {
            let matcher = Matcher::new(self.patterns);
            //println!("\n===\n trying to match {:?} on '{}'", self.patterns, input);
            if matcher
                .matches_at_start(&input[i..], &input[i..])
                .is_success()
            {
                return true;
            }
        }

        false
    }

    #[inline]
    fn fail(self) -> MatchResult<'a> {
        MatchResult::Fail(self.into_state())
    }

    #[inline]
    fn success(self, match_len: usize) -> MatchResult<'a> {
        MatchResult::Success(match_len, self.into_state())
    }

    #[inline]
    fn into_state(self) -> MatcherState<'a> {
        MatcherState::new(self.group_id, self.open_groups, self.captures)
    }

    /// Matches all patterns from the start of the input.
    ///
    /// Returns the number of characters matched and the captures or None if no match was found.
    fn matches_at_start(mut self, full_input: &'a str, input: &'a str) -> MatchResult<'a> {
        let mut input = input;
        let start_input = input;

        let patterns = self.patterns.iter().enumerate();
        for (i, p) in patterns {
            //println!("trying: {:?} on '{}'", p, input);

            match p {
                PatternElement::Literal(c) => {
                    if !input.starts_with(*c) {
                        return self.fail();
                    }
                    //println!("{p:?} matched '{}'", &input[..1]);
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::Str(s) => {
                    if !input.starts_with(s) {
                        return self.fail();
                    }

                    //println!("{p:?} matched '{}'", &input[..s.len()]);
                    input = input.get(s.len()..).unwrap_or_default();
                }
                PatternElement::Digit => {
                    if let Some(c) = input.chars().next() {
                        if !c.is_ascii_digit() {
                            return self.fail();
                        }
                    } else {
                        return self.fail();
                    }
                    //println!("{p:?} matched '{}'", &input[..1]);
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::Alphanumeric => {
                    if let Some(c) = input.chars().next() {
                        if !(c.is_ascii_alphanumeric() || c == '_') {
                            return self.fail();
                        }
                    } else {
                        return self.fail();
                    }
                    //println!("{p:?} matched '{}'", &input[..1]);
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::PosCharGroup(chars) => {
                    if let Some(c) = input.chars().next() {
                        if !chars.contains(&c) {
                            return self.fail();
                        }
                    } else {
                        return self.fail();
                    }
                    //println!("{p:?} matched '{}'", &input[..1]);
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::NegCharGroup(chars) => {
                    if let Some(c) = input.chars().next() {
                        if chars.contains(&c) {
                            return self.fail();
                        }
                    } else {
                        return self.fail();
                    }
                    // println!("{p:?} matched '{}'", &input[..1]);
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::EndAnchor => {
                    if !input.is_empty() {
                        return self.fail();
                    }
                }
                PatternElement::Quantifier(p, min, max) => {
                    #[derive(Debug)]
                    struct Try<'a> {
                        input: &'a str,
                        inner_captures: Vec<&'a str>,
                    }

                    let p = p.as_ref();
                    match p {
                        PatternElement::GroupEnd => {
                            unimplemented!("Repeated groups are not supported")
                        }
                        PatternElement::Quantifier(..) => {
                            unimplemented!("Nested + quantifiers are not supported")
                        }
                        _ => {}
                    }

                    // Idea here is to match `p` as many times as possible and save the state after each match.
                    // Then starting from the longest match try to match rest of the patterns.
                    // First pattern combination that succeeds is the one we should match.

                    let mut next_tries = Vec::new();
                    let following_patterns = self.patterns.get(i + 1..).unwrap_or_default();

                    let mut matches_count = 0;
                    while let MatchResult::Success(match_len, state) =
                        Matcher::new(std::slice::from_ref(p)).matches_at_start(full_input, input)
                    {
                        let MatcherState {
                            captures: inner_captures,
                            ..
                        } = state;

                        input = input.get(match_len..).unwrap_or_default();
                        matches_count += 1;

                        if matches_count < *min {
                            continue;
                        }
                        next_tries.push(Try {
                            input,
                            inner_captures,
                        });

                        if let Some(max) = max {
                            if matches_count >= *max {
                                break;
                            }
                        }
                    }

                    if matches_count < *min {
                        return self.fail();
                    }

                    if matches_count == 0 && *min == 0 {
                        continue;
                    }

                    assert!(matches_count >= *min);
                    assert!(matches_count <= max.unwrap_or(usize::MAX));

                    let orig_captures_len = self.captures.len();

                    //println!("next tries: {:?}", next_tries);
                    for next in next_tries.into_iter().rev() {
                        // add captures from the try if there were any,
                        // if this try fails, make sure to remove them before next try!
                        self.group_id += next.inner_captures.len();
                        self.captures.extend(next.inner_captures);
                        let captures = std::mem::take(&mut self.captures);
                        let matcher = Matcher::new_from_middle(
                            following_patterns,
                            self.group_id,
                            // we cannot mem::take open_groups because new matcher can also remove
                            //items from it and thus we cannot easily restore the state after a failed try
                            self.open_groups.clone(),
                            captures,
                        );

                        match matcher.matches_at_start(full_input, next.input) {
                            MatchResult::Success(match_len, state) => {
                                //println!("{:?} matched '{}'", next.0, &next.1[..end]);
                                input = next.input.get(match_len..).unwrap_or_default();
                                // println!(
                                //     "END: {:?} matched '{}'",
                                //     self.main_patterns,
                                //     &start_input[..start_input.len() - input.len()]
                                // );

                                return MatchResult::Success(
                                    start_input.len() - input.len() + match_len,
                                    state,
                                );
                            }
                            MatchResult::Fail(state) => {
                                self.captures = state.captures;

                                self.captures.truncate(orig_captures_len);
                            }
                        }
                    }

                    return self.fail();
                }
                PatternElement::Wildcard => {
                    input = input.get(1..).unwrap_or_default();
                }
                PatternElement::GroupStart => {
                    self.group_id += 1;
                    let id = self.group_id;
                    self.captures.push("");
                    self.open_groups.push((id, full_input.len() - input.len()));
                }
                PatternElement::GroupEnd => {
                    let (id, start) = self.open_groups.pop().unwrap();
                    let capture = &full_input[start..full_input.len() - input.len()];
                    //println!("group matched '{capture}'",);
                    self.captures[id - 1] = capture;
                }
                PatternElement::Alternation(lhs, rhs) => {
                    let mut matched = false;

                    let orig_captures_len = self.captures.len();
                    let orig_group_id = self.group_id;

                    for alt in [lhs, rhs] {
                        let captures = std::mem::take(&mut self.captures);

                        let matcher = Matcher::new_from_middle(
                            alt,
                            self.group_id,
                            self.open_groups.clone(),
                            captures,
                        );

                        match matcher.matches_at_start(full_input, input) {
                            MatchResult::Success(match_len, state) => {
                                input = input.get(match_len..).unwrap_or_default();
                                self.captures = state.captures;
                                self.open_groups = state.open_groups;
                                self.group_id = state.group_id;
                                matched = true;
                                break;
                            }
                            MatchResult::Fail(state) => {
                                self.captures = state.captures;

                                self.captures.truncate(orig_captures_len);
                                self.group_id = orig_group_id;
                            }
                        }
                    }

                    if !matched {
                        return self.fail();
                    }
                }
                PatternElement::BackRef(i) => {
                    assert!(*i > 0);
                    let capture = &self.captures[*i - 1];
                    if !input.starts_with(capture) {
                        return self.fail();
                    }

                    input = input.get(capture.len()..).unwrap_or_default();
                }
            }
        }
        // println!("captures: {:#?}", &self.captures);
        // println!(
        //     "END: {:?} matched '{}'",
        //     self.main_patterns,
        //     &start_input[..start_input.len() - input.len()]
        // );
        self.success(start_input.len() - input.len())
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
    EndAnchor,
    Quantifier(Box<PatternElement>, usize, Option<usize>),
    Wildcard,
    GroupStart,
    GroupEnd,
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
    fn test_nested_group() {
        let regex = Regex::new(r"a(b(g))");
        dbg!(&regex);
        assert!(regex.matches("abg"));
        assert!(!regex.matches("dgg"));
        assert!(!regex.matches("dys"));
    }

    #[test]
    fn test_one_or_more_not_full() {
        let regex = Regex::new(r"[^a]+, b");
        dbg!(&regex);
        assert!(regex.matches("bvd, b"));
        let regex = Regex::new(r"([^a]+), b");
        dbg!(&regex);
        assert!(regex.matches("bvd, b"));
        let regex = Regex::new(r"([^a]+)");
        dbg!(&regex);
        assert!(regex.matches("bvd, b"));
    }

    #[test]
    #[should_panic(expected = "Repeated groups are not supported")]
    fn test_repeated_groups() {
        let regex = Regex::new(r"(a)+");
        dbg!(&regex);
        assert!(regex.matches("a"));
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
        let regex = Regex::new(r"(a (b\w (a)) (\d b))");
        dbg!(&regex);
        assert!(regex.matches("a ba a 1 b "));
    }

    #[test]
    fn test_nested_back_refs() {
        let regex = Regex::new(r"('(cat) and \2') is the same as \1");
        dbg!(&regex);
        assert!(regex.matches("'cat and cat' is the same as 'cat and cat'"));
    }

    #[test]
    fn test_nested_back_refs2() {
        let regex = Regex::new(r"(([abc]+)-([def]+)) is \1, not ([^xyz]+),");
        dbg!(&regex);
        assert!(regex.matches("abc-def is abc-def, not efg, abc, or def"));

        let regex = Regex::new(r"(([abc]+)-([def]+)) is abc-def, not ([^xyz]+), abc, or def");
        dbg!(&regex);
        assert!(regex.matches("abc-def is abc-def, not efg, abc, or def"));
    }
}
