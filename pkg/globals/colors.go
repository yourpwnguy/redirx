package globals

import (
	"fmt"

	"github.com/fatih/color"
)

/* ---------- prepare Sprint funcs once ---------- */

var (
	blueBoldFn   = color.New(color.FgCyan, color.Bold).SprintFunc()
	yellowBoldFn = color.New(color.FgYellow, color.Bold).SprintFunc()
	greenBoldFn  = color.New(color.FgGreen, color.Bold).SprintFunc()
	redBoldFn    = color.New(color.FgRed, color.Bold).SprintFunc()
	cyanBoldFn   = color.New(color.FgCyan, color.Bold).SprintFunc()
	purpleBoldFn = color.New(color.FgMagenta, color.Bold).SprintFunc()
	whiteBoldFn  = color.New(color.FgWhite, color.Bold).SprintFunc()
)

/* ---------- generic helpers ---------- */

func ColorStatus(sc int) string {
	switch sc / 100 {
	case 2:
		return greenBoldFn(sc)
	case 3:
		return yellowBoldFn(sc)
	case 4:
		return redBoldFn(sc)
	case 5:
		return GrayBoldRGB(sc)
	default:
		return whiteBoldFn(sc)
	}
}

// works for string, int, float, whatever
func BlueBold[T any](v T) string   { return blueBoldFn(v) }
func YellowBold[T any](v T) string { return yellowBoldFn(v) }
func GreenBold[T any](v T) string  { return greenBoldFn(v) }
func RedBold[T any](v T) string    { return redBoldFn(v) }
func PurpleBold[T any](v T) string { return purpleBoldFn(v) }

// custom RGB (0,175,255) + bold
func CustomBlue[T any](v T) string {
	return fmt.Sprintf("\x1b[1m\x1b[38;2;0;175;255m%v\x1b[0m", v)
}

func GrayBoldRGB[T any](v T) string {
	return fmt.Sprintf("\x1b[1;38;2;160;160;160m%v\x1b[0m", v)
}

// Bold‑italic washed‑red (“REDIRX”)
var REDIRX = "\x1b[1;3;38;2;255;50;50mREDIRX\x1b[0m"
var ERR = color.New(color.FgRed, color.Bold).Sprint("ERR")
