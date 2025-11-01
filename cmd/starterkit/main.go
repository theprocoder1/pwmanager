package main

import (
	"appliedcryptography-starter-kit/internal/pwmanager"
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func usage() {
	fmt.Print(`Usage:
  go run ./cmd/starterkit --help
  go run ./cmd/starterkit init   --file vault.json --master MASTER
  go run ./cmd/starterkit add    --file vault.json --master MASTER --title "GitHub" --username "alice" --password "S3cret!" [--url ...] [--notes ...]
  go run ./cmd/starterkit list   --file vault.json
  go run ./cmd/starterkit show   --file vault.json --master MASTER (--id ENTRY_ID | --title "GitHub")
  go run ./cmd/starterkit ui     --file vault.json          (interactive menu)
`)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage()
		return
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "add":
		cmdAdd(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "show":
		cmdShow(os.Args[2:])
	case "ui":
		cmdUI(os.Args[2:])
	default:
		usage()
	}
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	file := fs.String("file", "vault.json", "path to vault file")
	master := fs.String("master", "", "master password (plain)")
	fs.Parse(args)
	require(*master != "", "master")
	v, _, err := pwmanager.Create(*master)
	check(err, "init")
	check(v.Save(*file), "save")
	fmt.Println("vault created at", *file)
}

func cmdAdd(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	file := fs.String("file", "vault.json", "path to vault file")
	master := fs.String("master", "", "master password (plain)")
	title := fs.String("title", "", "title")
	username := fs.String("username", "", "username")
	password := fs.String("password", "", "password")
	url := fs.String("url", "", "optional URL")
	notes := fs.String("notes", "", "optional notes")
	fs.Parse(args)
	require(*master != "", "master")
	require(*title != "", "title")
	require(*username != "", "username")
	require(*password != "", "password")

	v, err := pwmanager.Load(*file)
	check(err, "load")
	key, err := v.Unlock(*master)
	check(err, "unlock (check master password)")
	id, err := v.AddEntry(key, *title, *username, *password, *url, *notes)
	check(err, "add entry")
	check(v.Save(*file), "save")
	fmt.Println("added entry id:", id)
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	file := fs.String("file", "vault.json", "path to vault file")
	fs.Parse(args)
	v, err := pwmanager.Load(*file)
	check(err, "load")
	entries := v.List()
	if len(entries) == 0 {
		fmt.Println("(empty)")
		return
	}
	fmt.Println("ID                                   | Title         | Modified")
	fmt.Println(strings.Repeat("-", 88))
	for _, e := range entries {
		fmt.Printf("%-35s | %-13s | %s\n", e.ID, e.Title, e.ModifiedAt.Format("2006-01-02 15:04:05"))
	}
}

func cmdShow(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	file := fs.String("file", "vault.json", "path to vault file")
	master := fs.String("master", "", "master password (plain)")
	id := fs.String("id", "", "entry id")
	title := fs.String("title", "", "entry title (case-insensitive; allows partial match)")
	fs.Parse(args)
	require(*master != "", "master")
	if *id == "" && strings.TrimSpace(*title) == "" {
		fmt.Println("provide either --id or --title")
		os.Exit(1)
	}

	v, err := pwmanager.Load(*file)
	check(err, "load")
	key, err := v.Unlock(*master)
	check(err, "unlock")

	// resolve id from title if needed
	targetID := *id
	if targetID == "" {
		// prefer exact title; otherwise substring search
		exact := v.FindByExactTitle(*title)
		candidates := exact
		if len(candidates) == 0 {
			candidates = v.SearchTitles(*title)
		}
		if len(candidates) == 0 {
			fmt.Println("no entry found matching title:", *title)
			os.Exit(1)
		}
		if len(candidates) > 1 {
			// ask user to choose
			fmt.Println("Multiple matches:")
			for i, e := range candidates {
				fmt.Printf("  [%d] %-12s | %s | %s\n", i+1, e.Title, e.ID, e.ModifiedAt.Format("2006-01-02 15:04:05"))
			}
			fmt.Print("Pick number: ")
			var n int
			_, scanErr := fmt.Scanf("%d", &n)
			if scanErr != nil || n < 1 || n > len(candidates) {
				fmt.Println("invalid selection")
				os.Exit(1)
			}
			targetID = candidates[n-1].ID
		} else {
			targetID = candidates[0].ID
		}
	}

	plain, meta, err := v.GetDecrypted(key, targetID)
	check(err, "get")
	fmt.Println("Title:   ", meta.Title)
	fmt.Println("Username:", plain.Username)
	fmt.Println("Password:", plain.Password)
	if plain.URL != "" {
		fmt.Println("URL:     ", plain.URL)
	}
	if plain.Notes != "" {
		fmt.Println("Notes:   ", plain.Notes)
	}
}

func cmdUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	file := fs.String("file", "vault.json", "path to vault file")
	fs.Parse(args)

	v, err := pwmanager.Load(*file)
	check(err, "load")

	in := bufio.NewReader(os.Stdin)
	fmt.Println("=== Simple Password Manager ===")
	master := promptLine(in, "Enter master password (not hidden): ")
	key, err := v.Unlock(master)
	if err != nil {
		fmt.Println("Unlock failed:", err)
		return
	}
	fmt.Println("Unlocked ✔")

	for {
		fmt.Println()
		fmt.Println("[A]dd  [L]ist  [S]how(by title)  [D]elete  [Q]uit")
		choice := strings.ToLower(promptLine(in, "> "))

		switch choice {
		case "a", "add":
			title := promptLine(in, "Title: ")
			username := promptLine(in, "Username: ")
			password := promptLine(in, "Password: ")
			url := promptLine(in, "URL (optional): ")
			notes := promptLine(in, "Notes (optional): ")
			id, err := v.AddEntry(key, title, username, password, url, notes)
			if err != nil {
				fmt.Println("Add error:", err)
				continue
			}
			if err := v.Save(*file); err != nil {
				fmt.Println("Save error:", err)
				continue
			}
			fmt.Println("Added. ID:", id)

		case "l", "list":
			entries := v.List()
			if len(entries) == 0 {
				fmt.Println("(empty)")
				continue
			}
			fmt.Println("ID                                   | Title         | Modified")
			fmt.Println(strings.Repeat("-", 88))
			for _, e := range entries {
				fmt.Printf("%-35s | %-13s | %s\n", e.ID, e.Title, e.ModifiedAt.Format("2006-01-02 15:04:05"))
			}

		case "s", "show":
			query := promptLine(in, "Title (partial ok): ")
			cands := v.FindByExactTitle(query)
			if len(cands) == 0 {
				cands = v.SearchTitles(query)
			}
			if len(cands) == 0 {
				fmt.Println("No match.")
				continue
			}
			if len(cands) > 1 {
				fmt.Println("Multiple matches:")
				for i, e := range cands {
					fmt.Printf("  [%d] %-12s | %s\n", i+1, e.Title, e.ID)
				}
				num := promptLine(in, "Pick number: ")
				i := atoiSafe(num)
				if i < 1 || i > len(cands) {
					fmt.Println("Invalid selection.")
					continue
				}
				showOne(v, key, cands[i-1].ID)
			} else {
				showOne(v, key, cands[0].ID)
			}

		case "d", "delete":
			query := promptLine(in, "Title (partial ok): ")
			cands := v.FindByExactTitle(query)
			if len(cands) == 0 {
				cands = v.SearchTitles(query)
			}
			if len(cands) == 0 {
				fmt.Println("No match.")
				continue
			}
			var target string
			if len(cands) > 1 {
				for i, e := range cands {
					fmt.Printf("  [%d] %-12s | %s\n", i+1, e.Title, e.ID)
				}
				num := promptLine(in, "Pick number to delete: ")
				i := atoiSafe(num)
				if i < 1 || i > len(cands) {
					fmt.Println("Invalid selection.")
					continue
				}
				target = cands[i-1].ID
			} else {
				target = cands[0].ID
			}
			if ok := v.Delete(target); !ok {
				fmt.Println("No such entry.")
				continue
			}
			if err := v.Save(*file); err != nil {
				fmt.Println("Save error:", err)
				continue
			}
			fmt.Println("Deleted.")

		case "q", "quit":
			fmt.Println("Bye!")
			return

		default:
			fmt.Println("Unknown choice.")
		}
	}
}

func showOne(v *pwmanager.Vault, key []byte, id string) {
	plain, meta, err := v.GetDecrypted(key, id)
	if err != nil {
		fmt.Println("Show error:", err)
		return
	}
	fmt.Println("Title:   ", meta.Title)
	fmt.Println("Username:", plain.Username)
	fmt.Println("Password:", plain.Password)
	if plain.URL != "" {
		fmt.Println("URL:     ", plain.URL)
	}
	if plain.Notes != "" {
		fmt.Println("Notes:   ", plain.Notes)
	}
}

func promptLine(in *bufio.Reader, label string) string {
	fmt.Print(label)
	text, _ := in.ReadString('\n')
	return strings.TrimSpace(text)
}

func atoiSafe(s string) int {
	var n int
	fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n
}

func require(ok bool, name string) {
	if !ok {
		fmt.Printf("missing --%s\n", name)
		os.Exit(1)
	}
}
func check(err error, where string) {
	if err != nil {
		fmt.Printf("%s error: %v\n", where, err)
		os.Exit(1)
	}
}
