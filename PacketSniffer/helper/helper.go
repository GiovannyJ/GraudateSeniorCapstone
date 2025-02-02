package helper

import (
	"unicode"
	"fmt"
)

func isPrintable(b byte) bool {
    return unicode.IsPrint(rune(b))
}

func CleanPayload(payload []byte) string {
    result := ""
    for _, b := range payload {
        if isPrintable(b) || b == '\n' || b == '\r' {
            result += string(b)
        } else {
            result += "." // Replace non-printable characters
        }
    }
    return result
}

func Okay(message string, args ...interface{}){fmt.Printf("[+] " + message+"\n", args...)}
func Info(message string, args ...interface{}){fmt.Printf("[i] " + message+"\n", args...)}
func Warn(message string, args ...interface{}){fmt.Printf("[!] " + message+"\n", args...)}