//! Validates quoted or delimited sequences in iterators.
//!
//! Provides [`IterableQuoted`] to check if elements form a properly
//! delimited sequence (e.g., `"text"` or `<value>`).
//!
//! ```
//! use email_primitives::quotes::IterableQuoted;
//!
//! let data = vec!['"', 'h', 'e', 'l', 'l', 'o', '"'];
//! let is_quoted = data.into_iter().all_quoted(
//!     |c| *c == '"',
//!     |c| *c != '"',
//!     |c| *c == '"',
//! );
//! assert!(is_quoted);
//! ```

/// Check if iterator elements form a valid delimited sequence.
///
/// Validates sequences with opening, inner, and closing predicates.
/// Requires at least two elements. Returns `false` for empty or single-element iterators.
pub trait IterableQuoted<T> {
    /// Checks if all elements form a properly delimited sequence.
    ///
    /// Returns `true` if first satisfies `open`, all middle elements satisfy `inner`,
    /// and last satisfies `end`. Requires at least two elements.
    ///
    /// ```
    /// use email_primitives::quotes::IterableQuoted;
    ///
    /// let valid = vec!['"', 'a', 'b', '"'];
    /// assert!(valid.into_iter().all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"'));
    ///
    /// let empty: Vec<char> = vec![];
    /// assert!(!empty.into_iter().all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"'));
    /// ```
    fn all_quoted<O: Fn(&T) -> bool, I: Fn(&T) -> bool, E: Fn(&T) -> bool>(
        self,
        open: O,
        inner: I,
        end: E,
    ) -> bool;

    /// Checks if all elements match their respective predicates, including boundaries.
    ///
    /// Tests the first element against `open`, all elements (including first and last)
    /// against `inner`, and the last element against `end`. Returns `true` for empty
    /// iterators (succeeds unless an element exists and fails a test).
    ///
    /// # Differences from `all_quoted`
    ///
    /// Unlike `all_quoted`, which only checks `inner` on middle elements, this method
    /// applies the `inner` predicate to all elements including the opening and closing
    /// elements.
    ///
    /// ```
    /// use email_primitives::quotes::IterableQuoted;
    ///
    /// let valid = vec!['<', 'a', 'b', '>'];
    /// assert!(valid.into_iter().all_matching(
    ///     |c| *c == '<',
    ///     |c| *c != '"',
    ///     |c| *c == '>'
    /// ));
    ///
    /// let empty: Vec<char> = vec![];
    /// assert!(empty.into_iter().all_matching(|c| *c == '<', |c| *c != '"', |c| *c == '>'));
    /// ```
    fn all_matching<O: Fn(&T) -> bool, I: Fn(&T) -> bool, E: Fn(&T) -> bool>(
        self,
        open: O,
        inner: I,
        end: E,
    ) -> bool;
}

impl<T, Iter: Iterator<Item = T>> IterableQuoted<T> for Iter {
    fn all_quoted<O: Fn(&T) -> bool, I: Fn(&T) -> bool, E: Fn(&T) -> bool>(
        mut self,
        open: O,
        inner: I,
        end: E,
    ) -> bool {
        if let Some(first) = self.next() {
            if !open(&first) {
                return false;
            }
            if let Some(mut cur) = self.next() {
                loop {
                    if let Some(next) = self.next() {
                        if !inner(&cur) {
                            return false;
                        }
                        cur = next;
                    } else {
                        return end(&cur);
                    }
                }
            }
        }
        false
    }

    fn all_matching<O: Fn(&T) -> bool, I: Fn(&T) -> bool, E: Fn(&T) -> bool>(
        mut self,
        open: O,
        inner: I,
        end: E,
    ) -> bool {
        if let Some(mut cur) = self.next() {
            if !open(&cur) {
                return false;
            }
            loop {
                if !inner(&cur) {
                    return false;
                }
                if let Some(next) = self.next() {
                    cur = next;
                } else {
                    return end(&cur);
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_quoted_empty_iterator() {
        let data: Vec<char> = vec![];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_quoted_single_quote() {
        let data = vec!['"'];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_quoted_valid_quoted_string() {
        let data = vec!['"', 'h', 'e', 'l', 'l', 'o', '"'];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(result);
    }

    #[test]
    fn test_all_quoted_invalid_opening() {
        let data = vec!['h', 'e', 'l', 'l', 'o', '"'];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_quoted_invalid_ending() {
        let data = vec!['"', 'h', 'e', 'l', 'l', 'o'];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_quoted_invalid_inner_character() {
        let data = vec!['"', 'h', 'e', '"', 'l', 'o', '"'];
        let result = data
            .into_iter()
            .all_quoted(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_quoted_with_brackets() {
        let data = vec!['<', 'a', 'b', 'c', '>'];
        let result =
            data.into_iter()
                .all_quoted(|c| *c == '<', |c| *c != '<' && *c != '>', |c| *c == '>');
        assert!(result);
    }

    #[test]
    fn test_all_quoted_numbers() {
        let data = vec![0, 1, 2, 3, 4];
        let result = data
            .into_iter()
            .all_quoted(|n| *n == 0, |n| *n > 0 && *n < 4, |n| *n == 4);
        assert!(result);
    }

    #[test]
    fn test_all_quoted_numbers_invalid() {
        let data = vec![0, 1, 2, 5, 4];
        let result = data
            .into_iter()
            .all_quoted(|n| *n == 0, |n| *n > 0 && *n < 4, |n| *n == 4);
        assert!(!result);
    }

    #[test]
    fn test_all_matching_empty_iterator() {
        let data: Vec<char> = vec![];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(result);
    }

    #[test]
    fn test_all_matching_single_element() {
        let data = vec!['"'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '"', |c| *c == '"', |c| *c == '"');
        assert!(result);
    }

    #[test]
    fn test_all_matching_single_element_invalid_open() {
        let data = vec!['x'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '"', |_| true, |c| *c == 'x');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_single_element_invalid_inner() {
        let data = vec!['"'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '"', |c| *c != '"', |c| *c == '"');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_single_element_invalid_end() {
        let data = vec!['"'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '"', |c| *c == '"', |c| *c != '"');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_valid_sequence() {
        let data = vec!['<', 'a', 'b', '>'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '<', |c| *c != '"', |c| *c == '>');
        assert!(result);
    }

    #[test]
    fn test_all_matching_invalid_opening() {
        let data = vec!['x', 'a', 'b', '>'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '<', |c| *c != '"', |c| *c == '>');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_invalid_inner() {
        let data = vec!['<', 'a', '"', '>'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '<', |c| *c != '"', |c| *c == '>');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_invalid_ending() {
        let data = vec!['<', 'a', 'b', 'x'];
        let result = data
            .into_iter()
            .all_matching(|c| *c == '<', |c| *c != '"', |c| *c == '>');
        assert!(!result);
    }

    #[test]
    fn test_all_matching_inner_checks_boundaries() {
        let data = vec!['<', 'a', 'b', '>'];
        let result = data.into_iter().all_matching(
            |c| *c == '<',
            |c| *c == '<' || *c == '>' || (*c >= 'a' && *c <= 'z'),
            |c| *c == '>',
        );
        assert!(result);
    }
}
