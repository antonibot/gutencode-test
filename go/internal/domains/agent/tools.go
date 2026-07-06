package agent

// The tool belt: a registry that NEVER crashes (missing tool / bad input -> a graceful error observation) and
// the built-ins — calc (a recursive-descent parser over + - * / % and parentheses; NEVER an eval; one-decimal
// output so all three languages produce identical observations) and echo.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func runTool(name string, args map[string]string) (string, bool) {
	switch name {
	case "calc":
		return calc(args["expr"]), true
	case "echo":
		return args["text"], true
	default:
		return fmt.Sprintf("tool '%s' not found", name), false
	}
}

// ── calc: tokenizer + recursive descent (expr := term (('+'|'-') term)* · term := unary (('*'|'/'|'%') unary)*
//    · unary := '-' unary | atom · atom := number | '(' expr ')') ──────────────────────────────────────────────

type calcParser struct {
	tokens []string
	pos    int
}

func calc(expr string) string {
	p := &calcParser{tokens: calcTokens(expr)}
	if len(p.tokens) == 0 {
		return "error: invalid expression"
	}
	v, ok := p.parseExpr()
	if !ok || p.pos != len(p.tokens) {
		return "error: invalid expression"
	}
	if math.IsInf(v, 0) || math.IsNaN(v) { // ±Inf (1/0, overflow) / NaN -> invalid, matching python/node (one observation ×3)
		return "error: invalid expression"
	}
	return fmt.Sprintf("%.1f", v)
}

func calcTokens(expr string) []string {
	out := []string{}
	i := 0
	for i < len(expr) {
		c := expr[i]
		switch {
		case c == ' ':
			i++
		case strings.ContainsRune("+-*/%()", rune(c)):
			out = append(out, string(c))
			i++
		case (c >= '0' && c <= '9') || c == '.':
			j := i
			for j < len(expr) && ((expr[j] >= '0' && expr[j] <= '9') || expr[j] == '.') {
				j++
			}
			out = append(out, expr[i:j])
			i = j
		default:
			return nil // any other character -> invalid (never executed, never evaluated)
		}
	}
	return out
}

func (p *calcParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *calcParser) parseExpr() (float64, bool) {
	v, ok := p.parseTerm()
	if !ok {
		return 0, false
	}
	for p.peek() == "+" || p.peek() == "-" {
		op := p.tokens[p.pos]
		p.pos++
		r, ok := p.parseTerm()
		if !ok {
			return 0, false
		}
		if op == "+" {
			v += r
		} else {
			v -= r
		}
	}
	return v, true
}

func (p *calcParser) parseTerm() (float64, bool) {
	v, ok := p.parseUnary()
	if !ok {
		return 0, false
	}
	for p.peek() == "*" || p.peek() == "/" || p.peek() == "%" {
		op := p.tokens[p.pos]
		p.pos++
		r, ok := p.parseUnary()
		if !ok {
			return 0, false
		}
		switch op {
		case "*":
			v *= r
		case "/":
			v /= r
		default:
			if int64(r) == 0 { // int64 % 0 PANICS in Go (uncontained crash) -> reject, matching python/node 1%0
				return 0, false
			}
			v = float64(int64(v) % int64(r))
		}
	}
	return v, true
}

func (p *calcParser) parseUnary() (float64, bool) {
	if p.peek() == "-" {
		p.pos++
		v, ok := p.parseUnary()
		return -v, ok
	}
	if p.peek() == "(" {
		p.pos++
		v, ok := p.parseExpr()
		if !ok || p.peek() != ")" {
			return 0, false
		}
		p.pos++
		return v, true
	}
	tok := p.peek()
	if tok == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		return 0, false
	}
	p.pos++
	return v, true
}
