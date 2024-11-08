package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"

    "github.com/incogbyte/shosubgo/apishodan"
)

const Author = "inc0gbyt3"

func main() {
    // Define and parse flags
    domain := flag.String("d", "", "> Domain to find subdomains")
    shodanKey := flag.String("s", "", "> Shodan API key")
    apiKeyFile := flag.String("ak", "", "> API key file (1 per line)")
    verbose := flag.Bool("v", false, "> Show all output")
    fileName := flag.String("o", "", "> Save domains into a file")
    inputFile := flag.String("f", "", "> File containing domains to find subdomains")
    jsonFlag := flag.Bool("json", false, "> Save output in JSON format")
    flag.Parse()

    if *domain == "" && *inputFile == "" {
        fmt.Printf("[*] Usage: %s -d target.com -s shodanKey  [-f input_file]\n", os.Args[0])
        fmt.Printf("[*] Author: %s\n", Author)
        os.Exit(1)
    }

    // Load API keys
    var apiKeys []string
    if *apiKeyFile != "" {
        var err error
        apiKeys, err = readAPIKeysFromFile(*apiKeyFile)
        if err != nil {
            log.Fatalf("Failed to read API keys from file: %v", err)
        }
    } else if *shodanKey != "" {
        apiKeys = append(apiKeys, *shodanKey)
    }

    // Load domains
    var domains []string
    if *domain != "" {
        domains = append(domains, *domain)
    }
    if *inputFile != "" {
        fileDomains, err := readDomainsFromFile(*inputFile)
        if err != nil {
            log.Fatalf("Failed to read domains from file: %v", err)
        }
        domains = append(domains, fileDomains...)
    }

    // Track API key status
    workingKeys, invalidKeys, limitExceededKeys := 0, 0, 0

    fmt.Println("")

    for _, apiKeyStr := range apiKeys {
        apiKey := apishodan.New(apiKeyStr)
        info, err := apiKey.InfoAccount()
        if err != nil {
            switch err.Error() {
            case "invalid API key (HTTP 401)":
                invalidKeys++
                fmt.Printf("API Key %s: Invalid API key.\n", apiKeyStr)
            case "API key has hit its limit (HTTP 403)":
                limitExceededKeys++
                fmt.Printf("API Key %s: API key has hit its limit.\n", apiKeyStr)
            default:
                fmt.Printf("API Key %s: Error with Shodan API key: %v\n", apiKeyStr, err)
            }
        } else {
            workingKeys++
            fmt.Printf("[*] API Key %s: Working API Key.\n", apiKeyStr)
            // Display account info for verbose output
            if *verbose {
                fmt.Printf("\n[*] Credits: %d\n[*] Scan Credits: %d\n\n", info.QueryCredits, info.ScanCredits)
            }
        }
    }

    fmt.Printf("\n[*] Total API Keys: %d\n[*] Working API Keys: %d\n[*] Invalid API Keys: %d\n[*] API Keys hit their limit: %d\n\n",
        len(apiKeys), workingKeys, invalidKeys, limitExceededKeys)

    // Retrieve and display subdomains
    for _, domainSearch := range domains {
        subdomain, err := apishodan.New(apiKeys[0]).GetSubdomain(domainSearch) // Replace with proper key handling if needed
        if err != nil {
            fmt.Printf("Error fetching subdomains for domain %s: %v\n", domainSearch, err)
            continue
        }

        if len(subdomain.SubDomains) == 0 {
            fmt.Printf("No subdomains found for domain %s\n", domainSearch)
            continue
        }

        if *jsonFlag {
            jsonData, err := json.MarshalIndent(subdomain.SubDomains, "", "  ")
            if err != nil {
                log.Fatal("Error marshaling JSON:", err)
            }
            if *fileName != "" {
                writeFile(*fileName, string(jsonData))
            } else {
                fmt.Println(string(jsonData))
            }
        } else {
            for _, v := range subdomain.SubDomains {
                formattedSubdomain := fmt.Sprintf("%s.%s", v, domainSearch)
                fmt.Println(formattedSubdomain)
                if *fileName != "" {
                    writeFile(*fileName, formattedSubdomain+"\n")
                }
            }
        }
    }
}

// Reads API keys from a file
func readAPIKeysFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var apiKeys []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        apiKeys = append(apiKeys, scanner.Text())
    }
    return apiKeys, scanner.Err()
}

// Reads domains from a file
func readDomainsFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domains = append(domains, scanner.Text())
    }
    return domains, scanner.Err()
}

// Writes to a file with optional appending
func writeFile(filename, data string) {
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    if _, err := f.WriteString(data); err != nil {
        log.Fatal(err)
    }
    fmt.Printf("[*] Written to file: %s\n", filename)
}
