package redirect

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/yourpwnguy/redirx/pkg/globals"
)

// Colors vulnerable Parameter in an URL
func highlightParam(u *url.URL, key string) string {
	q := u.Query()

	enc := url.QueryEscape
	value := q.Get(key)

	encKey := enc(key)
	encVal := enc(value)

	needle := encKey + "=" + encVal       // exact encoded pair
	repl := globals.RedBold(encKey+"=") + // red “key=”
		globals.YellowBold(encVal) // yellow value

	newQuery := strings.Replace(q.Encode(), needle, repl, 1) // do actual replace

	return fmt.Sprintf("%s://%s%s?%s",
		u.Scheme, u.Host, u.Path, newQuery)
}
