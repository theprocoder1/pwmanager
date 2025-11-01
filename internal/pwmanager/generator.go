package pwmanager

import (
	"crypto/rand"
	"math/big"
	"strings"
	"unicode"
)

// PasswordOptions defines the configuration for password generation
type PasswordOptions struct {
	Length           int
	IncludeUpper     bool
	IncludeLower     bool
	IncludeNumbers   bool
	IncludeSymbols   bool
	ExcludeSimilar   bool // e.g., l, 1, I, o, 0, O
	ExcludeAmbiguous bool // e.g., { } [ ] ( ) / \ ' " ` ~ , ; : . < >
}

const (
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	numberChars  = "0123456789"
	symbolChars  = "!@#$%^&*_+-="
	similarChars = "il1Lo0O"
	ambigChars   = "{}[]()/'\"`,;:.<>\\"
)

// GeneratePassword creates a new password based on the provided options
func GeneratePassword(opts PasswordOptions) (string, error) {
	var chars strings.Builder
	var result strings.Builder

	// Build character set based on options
	if opts.IncludeUpper {
		chars.WriteString(upperChars)
	}
	if opts.IncludeLower {
		chars.WriteString(lowerChars)
	}
	if opts.IncludeNumbers {
		chars.WriteString(numberChars)
	}
	if opts.IncludeSymbols {
		chars.WriteString(symbolChars)
	}

	// Remove excluded characters if specified
	charSet := chars.String()
	if opts.ExcludeSimilar {
		for _, c := range similarChars {
			charSet = strings.ReplaceAll(charSet, string(c), "")
		}
	}
	if opts.ExcludeAmbiguous {
		for _, c := range ambigChars {
			charSet = strings.ReplaceAll(charSet, string(c), "")
		}
	}

	if charSet == "" {
		return "", nil
	}

	// Generate password
	length := opts.Length
	if length < 4 {
		length = 12 // default length
	}

	// Ensure at least one character from each selected type
	if opts.IncludeUpper {
		result.WriteByte(getRandomChar(upperChars))
		length--
	}
	if opts.IncludeLower {
		result.WriteByte(getRandomChar(lowerChars))
		length--
	}
	if opts.IncludeNumbers {
		result.WriteByte(getRandomChar(numberChars))
		length--
	}
	if opts.IncludeSymbols {
		result.WriteByte(getRandomChar(symbolChars))
		length--
	}

	// Fill remaining length with random characters
	for i := 0; i < length; i++ {
		result.WriteByte(getRandomChar(charSet))
	}

	// Shuffle the password
	password := []rune(result.String())
	for i := len(password) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password), nil
}

// getRandomChar returns a random character from the given string
func getRandomChar(chars string) byte {
	if len(chars) == 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	return chars[n.Int64()]
}

// AnalyzePasswordStrength returns a score from 0-100 and feedback
func AnalyzePasswordStrength(password string) (score int, feedback []string) {
	if len(password) == 0 {
		return 0, []string{"Password is empty"}
	}

	var (
		hasUpper, hasLower, hasNumber, hasSymbol bool
		categories                               int
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	// Count character categories
	if hasUpper {
		categories++
	}
	if hasLower {
		categories++
	}
	if hasNumber {
		categories++
	}
	if hasSymbol {
		categories++
	}

	// Base score calculation
	score = 0
	feedback = make([]string, 0)

	// Length contribution (up to 40 points)
	lengthScore := len(password) * 2
	if lengthScore > 40 {
		lengthScore = 40
	}
	score += lengthScore

	// Character variety contribution (up to 40 points)
	score += categories * 10

	// Additional checks and feedback
	if len(password) < 8 {
		feedback = append(feedback, "Password is too short")
	}
	if !hasUpper || !hasLower {
		feedback = append(feedback, "Mix upper and lowercase letters")
	}
	if !hasNumber {
		feedback = append(feedback, "Add numbers")
	}
	if !hasSymbol {
		feedback = append(feedback, "Add symbols")
	}

	// Bonus points for good length and all categories (up to 20 points)
	if len(password) >= 12 && categories == 4 {
		score += 20
	} else if len(password) >= 10 && categories >= 3 {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	// Final feedback based on score
	switch {
	case score >= 80:
		feedback = append(feedback, "Strong password!")
	case score >= 60:
		feedback = append(feedback, "Good password, but could be stronger")
	case score >= 40:
		feedback = append(feedback, "Moderate password - consider strengthening")
	default:
		feedback = append(feedback, "Weak password - needs improvement")
	}

	return score, feedback
}
