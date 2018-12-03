package npmaudit

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"unicode"
)

type pkg struct {
	deps    map[string]dependencyInfo
	devDeps map[string]dependencyInfo
}

type dependencyInfo struct {
	line       int
	constraint string
}

func parsePackage(content []byte) (*pkg, error) {
	p := &parser{Reader: bufio.NewReader(bytes.NewReader(content)), line: 1}
	kvs, err := p.readObject()
	if err != nil {
		return nil, fmt.Errorf("unable to read package.json: %s", err)
	}

	var ok bool
	var deps, devDeps []objectKey
	for _, kv := range kvs {
		if kv.key == "dependencies" {
			deps, ok = kv.value.([]objectKey)
			if !ok {
				return nil, fmt.Errorf("cannot find correct dependencies on package json")
			}
		}

		if kv.key == "devDependencies" {
			devDeps, ok = kv.value.([]objectKey)
			if !ok {
				return nil, fmt.Errorf("cannot find correct devDependencies on package json")
			}
		}
	}

	pkg := &pkg{
		deps:    make(map[string]dependencyInfo),
		devDeps: make(map[string]dependencyInfo),
	}

	for _, d := range deps {
		constraint, ok := d.value.(string)
		if !ok {
			return nil, fmt.Errorf("constraint of package %s is not a string", d.key)
		}

		pkg.deps[d.key] = dependencyInfo{
			line:       d.start,
			constraint: constraint,
		}
	}

	for _, d := range devDeps {
		constraint, ok := d.value.(string)
		if !ok {
			return nil, fmt.Errorf("constraint of package %s is not a string", d.key)
		}

		pkg.devDeps[d.key] = dependencyInfo{
			line:       d.start,
			constraint: constraint,
		}
	}

	return pkg, nil
}

type parser struct {
	*bufio.Reader
	line int
}

func (p *parser) readObject() ([]objectKey, error) {
	if err := p.skipSpaces(); err != nil {
		return nil, fmt.Errorf("expecting '{': %s", err)
	}

	if err := p.expect('{'); err != nil {
		return nil, err
	}

	kv, err := p.readObjectKeys()
	if err != nil {
		return nil, err
	}

	if err := p.skipSpaces(); err != nil {
		return nil, fmt.Errorf("expecting '{': %s", err)
	}

	if err := p.expect('}'); err != nil {
		return nil, err
	}

	return kv, nil
}

type objectKey struct {
	start int
	end   int
	key   string
	value interface{}
}

func (p *parser) readObjectKeys() ([]objectKey, error) {
	var kv []objectKey
	for {
		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting object key: %s", err)
		}

		peeked, err := p.Peek(1)
		if err != nil {
			return nil, err
		}

		if peeked[0] == ']' {
			break
		}

		start := p.line
		key, err := p.readString()
		if err != nil {
			return nil, fmt.Errorf("reading object key: %s", err)
		}

		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting ':': %s", err)
		}

		if err := p.expect(':'); err != nil {
			return nil, err
		}

		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting object key value: %s", err)
		}

		val, err := p.readValue()
		if err != nil {
			return nil, fmt.Errorf("reading object value: %s", err)
		}

		end := p.line

		kv = append(kv, objectKey{start, end, key, val})

		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting object key value: %s", err)
		}

		peeked, err = p.Peek(1)
		if err != nil {
			return nil, fmt.Errorf("expecting ',' or '}': %s", err)
		}

		if peeked[0] != ',' {
			break
		}

		if err := p.expect(','); err != nil {
			return nil, err
		}
	}

	return kv, nil
}

func (p *parser) readString() (string, error) {
	if err := p.expect('"'); err != nil {
		return "", err
	}

	var chars = []rune{'"'}

	var escaped bool
	for {
		r, _, err := p.ReadRune()
		if err != nil {
			return "", err
		}

		switch r {
		case '\\':
			if !escaped {
				escaped = true
				chars = append(chars, r)
				continue
			}
		case '"':
			if !escaped {
				return strconv.Unquote(string(append(chars, '"')))
			}
		}

		if escaped {
			escaped = false
		}

		chars = append(chars, r)
	}
}

func (p *parser) readValue() (interface{}, error) {
	peeked, err := p.Peek(1)
	if err != nil {
		return nil, err
	}

	switch peeked[0] {
	case '"':
		return p.readString()
	case '[':
		return p.readArray()
	case '{':
		return p.readObject()
	}

	var chars []rune
	for {
		r, _, err := p.ReadRune()
		if err != nil {
			return nil, nil
		}

		if unicode.IsSpace(r) || r == ',' || r == '}' {
			if err := p.UnreadRune(); err != nil {
				return nil, err
			}
			break
		}

		chars = append(chars, r)
	}

	return string(chars), nil
}

func (p *parser) readArray() ([]interface{}, error) {
	if err := p.expect('['); err != nil {
		return nil, fmt.Errorf("expecting '[': %s", err)
	}

	if err := p.skipSpaces(); err != nil {
		return nil, fmt.Errorf("expecting value: %s", err)
	}

	var values []interface{}
	for {
		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting value, ',' or ']': %s", err)
		}

		peeked, err := p.Peek(1)
		if err != nil {
			return nil, err
		}

		if peeked[0] == ']' {
			break
		}

		val, err := p.readValue()
		if err != nil {
			return nil, err
		}

		values = append(values, val)

		if err := p.skipSpaces(); err != nil {
			return nil, fmt.Errorf("expecting value, ',' or ']': %s", err)
		}

		peeked, err = p.Peek(1)
		if err != nil {
			return nil, err
		}

		if peeked[0] != ',' {
			break
		}

		if err := p.expect(','); err != nil {
			return nil, err
		}
	}

	return values, nil
}

func (p *parser) expect(target rune) error {
	r, _, err := p.ReadRune()
	if err != nil {
		return fmt.Errorf("expecting %q: %s", string(target), err)
	}
	if r != target {
		return fmt.Errorf("expecting %q, got %q", string(target), string(r))
	}
	return nil
}

func (p *parser) skipSpaces() error {
	for {
		r, _, err := p.ReadRune()
		if err != nil {
			return err
		}

		if r == '\n' {
			p.line++
		}

		if !unicode.IsSpace(r) {
			return p.UnreadRune()
		}
	}
}
