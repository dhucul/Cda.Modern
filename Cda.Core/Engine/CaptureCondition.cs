using System;
using System.Collections.Generic;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// A small, host-side capture condition — the analysis form of a data-driven /
    /// conditional hook. Every call is still recorded in-target; this decides which
    /// of those the host keeps, so a noisy broad trace can be narrowed, live, to
    /// "calls where arg0 == 0", "calls to CreateFile", "calls whose string argument
    /// contains 'secret'", and so on.
    ///
    /// Grammar: space-separated clauses, ALL of which must match (logical AND).
    ///   argN==V  argN!=V  argN&lt;V  argN&gt;V  argN&lt;=V  argN&gt;=V  argN&amp;V
    ///       Compare captured integer argument N (0-based) to V, where V is 0x-hex
    ///       or decimal. '&amp;' matches when (argN AND V) is non-zero (a flag test).
    ///       An argument that wasn't captured never matches.
    ///   name~TEXT   name!~TEXT
    ///       The callee's resolved name contains / does not contain TEXT.
    ///   str~TEXT    str!~TEXT
    ///       Any decoded string argument contains / does not contain TEXT.
    /// TEXT may not contain spaces; name/str matching is case-insensitive.
    /// </summary>
    public sealed class CaptureCondition
    {
        private readonly List<Func<CallRecord, Func<ulong, string?>?, bool>> _clauses;

        /// <summary>The original text the condition was parsed from.</summary>
        public string Source { get; }

        private CaptureCondition(string source, List<Func<CallRecord, Func<ulong, string?>?, bool>> clauses)
        {
            Source = source;
            _clauses = clauses;
        }

        /// <summary>
        /// Parse a condition. Empty / whitespace input returns null with no error
        /// (meaning "no condition — keep everything"); a malformed clause returns
        /// null with an error message.
        /// </summary>
        public static CaptureCondition? Parse(string? text, out string? error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(text)) return null;

            var clauses = new List<Func<CallRecord, Func<ulong, string?>?, bool>>();
            foreach (var token in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!TryParseClause(token, out var clause, out error)) return null;
                clauses.Add(clause);
            }
            return clauses.Count == 0 ? null : new CaptureCondition(text.Trim(), clauses);
        }

        /// <summary>True if <paramref name="rec"/> satisfies every clause.</summary>
        public bool Matches(CallRecord rec, Func<ulong, string?>? nameOf)
        {
            foreach (var c in _clauses)
                if (!c(rec, nameOf)) return false;
            return true;
        }

        private static bool TryParseClause(string token,
            out Func<CallRecord, Func<ulong, string?>?, bool> clause, out string? error)
        {
            clause = (_, __) => true;
            error = null;

            if (token.StartsWith("name!~", StringComparison.OrdinalIgnoreCase))
            { string t = token.Substring(6); clause = (r, nm) => !NameContains(r, nm, t); return true; }
            if (token.StartsWith("name~", StringComparison.OrdinalIgnoreCase))
            { string t = token.Substring(5); clause = (r, nm) => NameContains(r, nm, t); return true; }

            if (token.StartsWith("str!~", StringComparison.OrdinalIgnoreCase))
            { string t = token.Substring(5); clause = (r, _) => !StringContains(r, t); return true; }
            if (token.StartsWith("str~", StringComparison.OrdinalIgnoreCase))
            { string t = token.Substring(4); clause = (r, _) => StringContains(r, t); return true; }

            if (token.StartsWith("arg", StringComparison.OrdinalIgnoreCase))
                return TryParseArgClause(token, out clause, out error);

            error = "unrecognized clause: " + token;
            return false;
        }

        private static bool TryParseArgClause(string token,
            out Func<CallRecord, Func<ulong, string?>?, bool> clause, out string? error)
        {
            clause = (_, __) => true;
            error = null;

            // Longest operators first so "<=" / ">=" aren't read as "<" / ">".
            string[] ops = { "==", "!=", "<=", ">=", "<", ">", "&" };
            int opPos = -1; string op = "";
            foreach (var o in ops)
            {
                int p = token.IndexOf(o, 3, StringComparison.Ordinal);
                if (p >= 0 && (opPos < 0 || p < opPos)) { opPos = p; op = o; }
            }
            if (opPos < 0) { error = "missing operator in: " + token; return false; }

            string idxText = token.Substring(3, opPos - 3);
            string valText = token.Substring(opPos + op.Length);
            if (!int.TryParse(idxText, out int idx) || idx < 0)
            { error = "bad argument index in: " + token; return false; }
            if (!TryParseValue(valText, out ulong val))
            { error = "bad value in: " + token; return false; }

            string fixedOp = op;
            clause = (r, _) =>
            {
                var a = r.IntegerArgs;
                if (a == null || idx >= a.Length) return false; // not captured -> can't match
                ulong x = a[idx];
                return fixedOp switch
                {
                    "==" => x == val,
                    "!=" => x != val,
                    "<" => x < val,
                    ">" => x > val,
                    "<=" => x <= val,
                    ">=" => x >= val,
                    "&" => (x & val) != 0,
                    _ => false,
                };
            };
            return true;
        }

        private static bool TryParseValue(string s, out ulong val)
        {
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                try { val = Convert.ToUInt64(s.Substring(2), 16); return true; }
                catch { val = 0; return false; }
            }
            return ulong.TryParse(s, out val);
        }

        private static bool NameContains(CallRecord r, Func<ulong, string?>? nameOf, string text)
        {
            string? n = nameOf?.Invoke(r.Destination);
            return !string.IsNullOrEmpty(n) && n!.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool StringContains(CallRecord r, string text)
        {
            if (r.Dereferences == null) return false;
            foreach (var d in r.Dereferences)
            {
                string? s = d.AsString();
                if (s != null && s.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }
    }
}
