package main

import (
	"fmt"
	"os"

	"appliedcryptography-starter-kit/internal/pwmanager"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: go run delete_entry.go <vault.json> <entryID>")
		os.Exit(1)
	}
	path := os.Args[1]
	id := os.Args[2]
	v, err := pwmanager.Load(path)
	if err != nil {
		fmt.Println("load error:", err)
		os.Exit(1)
	}
	ok := v.Delete(id)
	if !ok {
		fmt.Println("delete returned false: id not found")
		os.Exit(2)
	}
	if err := v.Save(path); err != nil {
		fmt.Println("save error:", err)
		os.Exit(1)
	}
	fmt.Println("deleted", id)
}
