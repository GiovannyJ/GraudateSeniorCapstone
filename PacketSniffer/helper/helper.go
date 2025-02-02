package helper

import (
	"unicode"

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