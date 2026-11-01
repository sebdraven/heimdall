package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestReadPrefixes(t *testing.T) {
	got, err := readPrefixes(strings.NewReader(`# provider list
192.0.2.0/24
  2001:db8::/32   # v6

198.51.100.7
192.0.2.0/24
`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(got), "[192.0.2.0/24 2001:db8::/32 198.51.100.7/32]"; got != want {
		t.Errorf("prefixes = %s, want %s", got, want)
	}

	_, err = readPrefixes(strings.NewReader("192.0.2.0/24\n192.0.2.1/24\ncdn.example\n"))
	if err == nil {
		t.Fatal("invalid lines accepted")
	}
	for _, want := range []string{"2 invalid line(s), nothing imported", "line 2: ", "use 192.0.2.0/24", "line 3: "} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}

	if got, err := readPrefixes(strings.NewReader("# empty\n\n")); err != nil || len(got) != 0 {
		t.Errorf("comments only: %v, %v", got, err)
	}
}
