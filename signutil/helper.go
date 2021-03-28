package main

import (
	"bytes"
	"fmt"
	"os"
	"io/ioutil"
	"github.com/imacks/signkey"
)

func readKeyPipe() ([]byte, error) {
	var key []byte

    fi, fiErr := os.Stdin.Stat()
    if fiErr != nil {
		return nil, fiErr
	}

    if (fi.Mode() & os.ModeCharDevice) != 0 {
		return nil, fmt.Errorf("no pipe content")
	}

    content, err := ioutil.ReadAll(os.Stdin)
    if err != nil {
		return nil, err
	}

	defer resetSlice(content)

	if signkey.IsKey(content) {
        key = make([]byte, len(content))
        copy(key, content)
        return key, nil
	}

    if key == nil {
        return nil, fmt.Errorf("invalid key")
    }

    return key, nil
}

func readKeyFile(filename string) ([]byte, error) {
	var key []byte

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	defer resetSlice(content)

	lines := bytes.Split(content, []byte("\n"))
	for _, line := range lines {
		if signkey.IsKey(line) {
			key = make([]byte, len(line))
			copy(key, line)
			return key, nil
		}
	}

	if key == nil {
		return nil, fmt.Errorf("invalid key")
	}
	
	return key, nil
}

func resetSlice(buf []byte) {
	for i := range buf {
		buf[i] = '0'
	}
}

func assertFatal(err error) {
	if err == nil {
		return
	}

	fmt.Printf("%v\n", err)
	os.Exit(1)
}